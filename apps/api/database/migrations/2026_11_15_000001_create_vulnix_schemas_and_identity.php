<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Esquemas lógicos (manual §5): identity, catalog, evaluation, audit.
 * Identidad: usuarios con rol RBAC (manual §11: developer, security_reviewer, approver, admin, auditor).
 */
return new class extends Migration
{
    public function up(): void
    {
        foreach (['identity', 'catalog', 'evaluation', 'audit'] as $schema) {
            DB::statement("CREATE SCHEMA IF NOT EXISTS {$schema}");
        }

        Schema::create('identity.users', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->string('username', 64)->unique();
            $t->string('display_name', 120);
            $t->string('email', 190)->nullable()->unique();
            $t->string('password_hash', 255);
            $t->string('role', 32);
            $t->boolean('active')->default(true);
            $t->smallInteger('failed_logins')->default(0);
            $t->timestampTz('locked_until')->nullable();
            $t->timestampTz('last_login_at')->nullable();
            $t->rememberToken();
            $t->timestampsTz();
        });
        DB::statement("ALTER TABLE identity.users ADD CONSTRAINT users_role_chk
            CHECK (role IN ('developer','security_reviewer','approver','admin','auditor'))");
        DB::statement("ALTER TABLE identity.users ADD CONSTRAINT users_username_chk
            CHECK (username ~ '^[a-z0-9._-]{3,64}$')");

        // Sesiones web (SPA mismo origen con CSRF). user_id es UUID.
        Schema::create('sessions', function (Blueprint $t) {
            $t->string('id')->primary();
            $t->uuid('user_id')->nullable()->index();
            $t->string('ip_address', 45)->nullable();
            $t->text('user_agent')->nullable();
            $t->longText('payload');
            $t->integer('last_activity')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('identity.users');
        foreach (['audit', 'evaluation', 'catalog', 'identity'] as $schema) {
            DB::statement("DROP SCHEMA IF EXISTS {$schema} CASCADE");
        }
    }
};
