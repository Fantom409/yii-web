<?php

declare(strict_types=1);

namespace Yiisoft\Yii\Web\Tests\Middleware;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yiisoft\Di\Container;
use Yiisoft\Log\Logger;
use Yiisoft\Yii\Web\ErrorHandler\ErrorHandler;
use Yiisoft\Yii\Web\ErrorHandler\ErrorCatcher;
use Yiisoft\Yii\Web\Tests\Middleware\Mock\MockRequestHandler;
use Yiisoft\Yii\Web\Tests\Middleware\Mock\MockThrowableRenderer;

class ErrorCatcherTest extends TestCase
{
    private const DEFAULT_RENDERER_RESPONSE = 'default-renderer-test';

    public function testAddedRenderer(): void
    {
        $expectedRendererOutput = 'expectedRendererOutput';
        $containerId = 'testRenderer';
        $container = $this->getContainerWithThrowableRenderer($containerId, $expectedRendererOutput);
        $mimeType = 'test/test';
        $catcher = $this->getErrorCatcher($container)->withRenderer($mimeType, $containerId);
        $response = $catcher->process(
            new ServerRequest('GET', '/', ['Accept' => [$mimeType]]),
            $this->getRequestHandler()
        );
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertNotSame(self::DEFAULT_RENDERER_RESPONSE, $content);
        $this->assertSame($expectedRendererOutput, $content);
    }

    public function testAddedOnlyOneRenderer(): void
    {
        $expectedRendererOutput = 'expectedRendererOutput';
        $containerId = 'testRenderer';
        $container = $this->getContainerWithThrowableRenderer($containerId, $expectedRendererOutput);
        $mimeType = 'test/test';
        $catcher = $this->getErrorCatcher($container)->withOnlyRenderer($mimeType, $containerId);
        $requestHandler = $this->getRequestHandler();

        $response = $catcher->process(new ServerRequest('GET', '/', ['Accept' => [$mimeType]]), $requestHandler);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertNotSame(self::DEFAULT_RENDERER_RESPONSE, $content);
        $this->assertSame($expectedRendererOutput, $content);

        $response = $catcher->process(new ServerRequest('GET', '/', ['Accept' => ['text/xml']]), $requestHandler);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertSame(self::DEFAULT_RENDERER_RESPONSE, $content);
    }

    public function testThrownExceptionWithNotExistsRenderer()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectErrorMessage('The renderer "InvalidRendererClass" cannot be found.');

        $this->getErrorCatcher(new Container())->withRenderer('test/test', \InvalidRendererClass::class);
    }

    public function testThrownExceptionWithInvalidMimeType()
    {
        $containerId = 'testRenderer';
        $container = $this->getContainerWithThrowableRenderer($containerId, '');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectErrorMessage('Invalid mime type.');

        $this->getErrorCatcher($container)->withRenderer('test invalid mimeType', $containerId);
    }

    public function testWithoutRenderers(): void
    {
        $container = new Container();
        $response = $this->getErrorCatcher($container)
            ->withoutRenderers()
            ->process(
                new ServerRequest('GET', '/', ['Accept' => ['test/html']]),
                $this->getRequestHandler()
            );

        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertSame(self::DEFAULT_RENDERER_RESPONSE, $content);
    }

    public function testWithoutRenderer(): void
    {
        $container = new Container();
        $response = $this->getErrorCatcher($container)
            ->withoutRenderers('*/*')
            ->process(
                new ServerRequest('GET', '/', ['Accept' => ['test/html']]),
                $this->getRequestHandler()
            );

        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertSame(self::DEFAULT_RENDERER_RESPONSE, $content);
    }

    public function testAdvancedAcceptHeader(): void
    {
        $containerId = 'testRenderer';
        $expectedRendererOutput = 'expectedRendererOutput';
        $container = $this->getContainerWithThrowableRenderer($containerId, $expectedRendererOutput);
        $mimeType = 'text/html;version=2';
        $catcher = $this->getErrorCatcher($container)->withRenderer($mimeType, $containerId);
        $response = $catcher->process(
            new ServerRequest('GET', '/', ['Accept' => ['text/html', $mimeType]]),
            $this->getRequestHandler()
        );
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertNotSame(self::DEFAULT_RENDERER_RESPONSE, $content);
    }

    public function testDefaultContentType(): void
    {
        $expectedRendererOutput = 'expectedRendererOutput';
        $containerId = 'testRenderer';
        $container = $this->getContainerWithThrowableRenderer($containerId, $expectedRendererOutput);
        $catcher = $this->getErrorCatcher($container)
            ->withRenderer('*/*', $containerId);
        $response = $catcher->process(
            new ServerRequest('GET', '/', ['Accept' => ['test/test']]),
            $this->getRequestHandler()
        );
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();
        $this->assertNotSame(self::DEFAULT_RENDERER_RESPONSE, $content);
        $this->assertSame($expectedRendererOutput, $content);
    }

    private function getContainerWithThrowableRenderer(string $id, string $expectedOutput): Container
    {
        return new Container(
            [
                $id => new MockThrowableRenderer($expectedOutput)
            ]
        );
    }

    private function getErrorHandler(): ErrorHandler
    {
        return new ErrorHandler(new Logger(), new MockThrowableRenderer(self::DEFAULT_RENDERER_RESPONSE));
    }

    private function getFactory(): ResponseFactoryInterface
    {
        return new Psr17Factory();
    }

    private function getErrorCatcher(Container $container): ErrorCatcher
    {
        return new ErrorCatcher($this->getFactory(), $this->getErrorHandler(), $container);
    }

    private function getRequestHandler(): RequestHandlerInterface
    {
        return (new MockRequestHandler())->setHandleExcaption(new \RuntimeException());
    }
}
