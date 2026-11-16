<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Catálogo: proyectos, versiones (artefactos inmutables), analizadores, políticas versionadas
 * e inteligencia de vulnerabilidades sincronizada offline.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('catalog.projects', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->string('name', 150);
            $t->string('slug', 160)->unique();
            $t->text('description')->nullable();
            $t->foreignUuid('owner_id')->constrained('identity.users');
            $t->string('criticality', 16);
            $t->string('default_profile', 64);
            $t->timestampsTz();
            $t->index('owner_id');
            $t->index('created_at');
        });
        DB::statement("ALTER TABLE catalog.projects ADD CONSTRAINT projects_criticality_chk
            CHECK (criticality IN ('LOW','MEDIUM','HIGH','CRITICAL'))");

        Schema::create('catalog.project_versions', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('project_id')->constrained('catalog.projects');
            $t->string('version', 64);
            $t->char('sha256', 64);
            $t->string('uri', 255);
            $t->string('artifact_kind', 16);
            $t->string('original_filename', 255);
            $t->bigInteger('size_bytes');
            $t->integer('file_count');
            $t->jsonb('manifest_json');
            $t->jsonb('technologies');
            $t->foreignUuid('created_by')->constrained('identity.users');
            $t->timestampTz('created_at')->useCurrent();
            $t->unique(['project_id', 'version']);
            $t->index('sha256');
            $t->index('created_at');
        });
        DB::statement("ALTER TABLE catalog.project_versions ADD CONSTRAINT pv_sha256_chk CHECK (sha256 ~ '^[0-9a-f]{64}$')");
        DB::statement("ALTER TABLE catalog.project_versions ADD CONSTRAINT pv_kind_chk CHECK (artifact_kind IN ('ZIP','FILE'))");
        DB::statement("ALTER TABLE catalog.project_versions ADD CONSTRAINT pv_version_chk CHECK (version ~ '^[A-Za-z0-9._+-]{1,64}$')");

        Schema::create('catalog.analyzers', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->string('name', 64);
            $t->string('version', 64);
            $t->string('category', 16);
            $t->char('config_hash', 64);
            $t->jsonb('metadata')->default('{}');
            $t->boolean('healthy')->default(false);
            $t->timestampTz('last_seen_at')->nullable();
            $t->timestampTz('created_at')->useCurrent();
            $t->unique(['name', 'version', 'config_hash']);
        });
        DB::statement("ALTER TABLE catalog.analyzers ADD CONSTRAINT analyzers_category_chk
            CHECK (category IN ('sast','sca','secrets','quality','dast'))");

        Schema::create('catalog.policies', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->string('code', 64);
            $t->string('version', 32);
            $t->jsonb('rules_json');
            $t->char('sha256', 64);
            $t->text('source_yaml')->nullable();
            $t->string('status', 16)->default('DRAFT');
            $t->foreignUuid('created_by')->nullable()->constrained('identity.users');
            $t->foreignUuid('approved_by')->nullable()->constrained('identity.users');
            $t->timestampTz('approved_at')->nullable();
            $t->timestampTz('created_at')->useCurrent();
            $t->unique(['code', 'version']);
            $t->index(['code', 'status']);
        });
        DB::statement("ALTER TABLE catalog.policies ADD CONSTRAINT policies_status_chk
            CHECK (status IN ('DRAFT','ACTIVE','RETIRED'))");
        // Segregación de funciones: quien crea una política no puede aprobarla.
        DB::statement("ALTER TABLE catalog.policies ADD CONSTRAINT policies_sod_chk
            CHECK (approved_by IS NULL OR created_by IS NULL OR approved_by <> created_by)");

        Schema::create('catalog.intel_feeds', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->string('ecosystem', 32);
            $t->string('source', 255);
            $t->char('sha256', 64);
            $t->integer('record_count');
            $t->timestampTz('imported_at')->useCurrent();
            $t->index(['ecosystem', 'imported_at']);
        });

        Schema::create('catalog.advisories', function (Blueprint $t) {
            $t->string('osv_id', 128);
            $t->string('ecosystem', 32);
            $t->string('package_name', 255);
            $t->string('severity', 16)->nullable();
            $t->jsonb('data');
            $t->timestampTz('modified')->nullable();
            $t->foreignUuid('feed_id')->constrained('catalog.intel_feeds');
            $t->primary(['osv_id', 'ecosystem', 'package_name']);
            $t->index(['ecosystem', 'package_name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('catalog.advisories');
        Schema::dropIfExists('catalog.intel_feeds');
        Schema::dropIfExists('catalog.policies');
        Schema::dropIfExists('catalog.analyzers');
        Schema::dropIfExists('catalog.project_versions');
        Schema::dropIfExists('catalog.projects');
    }
};
