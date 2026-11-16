<?php

namespace App\Http\Controllers;

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/** Sirve el frontend estático (apps/web) desde el mismo origen, con lista blanca de tipos. */
class WebAppController extends Controller
{
    private const TYPES = [
        'js' => 'text/javascript; charset=utf-8', 'css' => 'text/css; charset=utf-8', 'svg' => 'image/svg+xml',
        'png' => 'image/png', 'ico' => 'image/x-icon', 'woff2' => 'font/woff2', 'html' => 'text/html; charset=utf-8',
    ];

    public function index(): BinaryFileResponse
    {
        return $this->serve('index.html', 'no-cache');
    }

    public function asset(string $path): BinaryFileResponse
    {
        return $this->serve('assets/'.$path, 'no-cache');
    }

    private function serve(string $relative, string $cache): BinaryFileResponse
    {
        $root = realpath(config('vulnix.web_root'));
        $file = $root ? realpath($root.DIRECTORY_SEPARATOR.$relative) : false;
        $ext = strtolower(pathinfo((string) $file, PATHINFO_EXTENSION));
        if (! $file || ! is_file($file) || ! str_starts_with($file, $root.DIRECTORY_SEPARATOR) || ! isset(self::TYPES[$ext])) {
            throw new NotFoundHttpException;
        }

        return response()->file($file, ['Content-Type' => self::TYPES[$ext], 'Cache-Control' => $cache]);
    }
}
