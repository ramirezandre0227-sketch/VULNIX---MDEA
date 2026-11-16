<?php

namespace App\Providers;

use App\Support\DataStore;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(DataStore::class);
    }

    public function boot(): void
    {
        // Atributos no declarados o lazy loading inesperado son errores en desarrollo.
        Model::preventSilentlyDiscardingAttributes(! $this->app->isProduction());

        // Rate limits (manual §6).
        RateLimiter::for('api', fn (Request $r) => Limit::perMinute(240)->by($r->user()?->id ?: $r->ip()));
        // El bloqueo de cuenta (5 fallos) actúa antes que el rate limit; este frena la enumeración masiva.
        RateLimiter::for('login', fn (Request $r) => [
            Limit::perMinute(30)->by('ip:'.$r->ip()),
            Limit::perMinute(10)->by('user:'.strtolower((string) $r->input('username')).'|'.$r->ip()),
        ]);
        RateLimiter::for('uploads', fn (Request $r) => Limit::perMinute(10)->by($r->user()?->id ?: $r->ip()));
        RateLimiter::for('internal', fn (Request $r) => Limit::perMinute(600)->by($r->ip()));
    }
}
