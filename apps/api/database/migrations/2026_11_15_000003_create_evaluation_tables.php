<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Evaluación: análisis, jobs, hallazgos, evidencias, recomendaciones, decisiones, excepciones y reportes.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('evaluation.analyses', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('version_id')->constrained('catalog.project_versions');
            $t->foreignUuid('policy_id')->constrained('catalog.policies');
            $t->string('profile', 64);
            $t->string('status', 16)->default('CREATED');
            $t->text('status_reason')->nullable();
            $t->char('artifact_sha256', 64);
            $t->jsonb('dynamic_testing')->default('{"enabled": false}');
            $t->foreignUuid('requested_by')->constrained('identity.users');
            $t->string('client_request_key', 128)->nullable();
            $t->timestampTz('created_at')->useCurrent();
            $t->timestampTz('started_at')->nullable();
            $t->timestampTz('finished_at')->nullable();
            $t->timestampTz('updated_at')->nullable();
            $t->index('status');
            $t->index('version_id');
            $t->index('created_at');
            $t->unique(['requested_by', 'client_request_key']);
        });
        DB::statement("ALTER TABLE evaluation.analyses ADD CONSTRAINT analyses_status_chk CHECK (status IN
            ('CREATED','VALIDATING','QUEUED','RUNNING','NORMALIZING','EVALUATING','COMPLETED',
             'FAILED','CANCELLED','TIMED_OUT','INCONCLUSIVE'))");

        Schema::create('evaluation.scan_jobs', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('analysis_id')->constrained('evaluation.analyses');
            $t->foreignUuid('analyzer_id')->nullable()->constrained('catalog.analyzers');
            $t->string('analyzer_name', 64);
            $t->string('category', 16);
            $t->boolean('mandatory');
            $t->smallInteger('attempt')->default(1);
            $t->smallInteger('max_attempts')->default(2);
            $t->string('status', 16)->default('QUEUED');
            $t->char('idempotency_key', 64)->unique();
            $t->string('locked_by', 128)->nullable();
            $t->timestampTz('lease_expires_at')->nullable();
            $t->timestampTz('started_at')->nullable();
            $t->timestampTz('ended_at')->nullable();
            $t->integer('exit_code')->nullable();
            $t->string('error_type', 64)->nullable();
            $t->text('error_message')->nullable();
            $t->jsonb('metadata')->default('{}');
            $t->timestampTz('created_at')->useCurrent();
            $t->timestampTz('updated_at')->nullable();
            $t->unique(['analysis_id', 'analyzer_name', 'attempt']);
            $t->index(['status', 'created_at']);
            $t->index('analysis_id');
        });
        DB::statement("ALTER TABLE evaluation.scan_jobs ADD CONSTRAINT jobs_status_chk CHECK (status IN
            ('QUEUED','RUNNING','SUCCEEDED','FAILED','TIMED_OUT','CANCELLED','SKIPPED'))");
        DB::statement("ALTER TABLE evaluation.scan_jobs ADD CONSTRAINT jobs_category_chk
            CHECK (category IN ('sast','sca','secrets','quality','dast'))");

        Schema::create('evaluation.findings', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('analysis_id')->constrained('evaluation.analyses');
            $t->foreignUuid('job_id')->constrained('evaluation.scan_jobs');
            $t->string('fingerprint', 80);
            $t->string('correlation_key', 80)->nullable();
            $t->string('rule_id', 160);
            $t->string('analyzer_name', 64);
            $t->string('category', 16);
            $t->string('title', 255);
            $t->text('description');
            $t->string('severity', 16);
            $t->string('confidence', 16);
            $t->string('file_path', 1024)->nullable();
            $t->integer('start_line')->nullable();
            $t->integer('end_line')->nullable();
            $t->string('cwe', 32)->nullable();
            $t->text('snippet')->nullable();
            $t->text('remediation')->nullable();
            $t->string('status', 16)->default('OPEN');
            $t->jsonb('metadata')->default('{}');
            $t->timestampTz('created_at')->useCurrent();
            $t->unique(['job_id', 'fingerprint']);
            $t->index('analysis_id');
            $t->index('fingerprint');
            $t->index('severity');
            $t->index(['analysis_id', 'severity']);
        });
        DB::statement("ALTER TABLE evaluation.findings ADD CONSTRAINT findings_sev_chk
            CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'))");
        DB::statement("ALTER TABLE evaluation.findings ADD CONSTRAINT findings_conf_chk
            CHECK (confidence IN ('HIGH','MEDIUM','LOW'))");
        DB::statement("ALTER TABLE evaluation.findings ADD CONSTRAINT findings_status_chk
            CHECK (status IN ('OPEN'))");

        Schema::create('evaluation.evidences', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('finding_id')->nullable()->constrained('evaluation.findings');
            $t->foreignUuid('job_id')->nullable()->constrained('evaluation.scan_jobs');
            $t->string('kind', 32);
            $t->string('uri', 512);
            $t->char('sha256', 64);
            $t->bigInteger('size_bytes');
            $t->timestampTz('created_at')->useCurrent();
            $t->index('finding_id');
            $t->index('job_id');
        });
        DB::statement('ALTER TABLE evaluation.evidences ADD CONSTRAINT evidences_owner_chk
            CHECK (finding_id IS NOT NULL OR job_id IS NOT NULL)');

        Schema::create('evaluation.recommendations', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('finding_id')->constrained('evaluation.findings');
            $t->text('description');
            $t->text('verify');
            $t->jsonb('references')->default('[]');
            $t->timestampTz('created_at')->useCurrent();
            $t->index('finding_id');
        });

        Schema::create('evaluation.decisions', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('analysis_id')->constrained('evaluation.analyses');
            $t->foreignUuid('policy_id')->constrained('catalog.policies');
            $t->string('result', 20);
            $t->jsonb('reason_json');
            $t->char('artifact_sha256', 64);
            $t->char('policy_sha256', 64);
            $t->string('signed_token_uri', 512);
            $t->char('token_sha256', 64);
            $t->string('key_id', 32);
            $t->timestampTz('issued_at');
            $t->timestampTz('expires_at');
            $t->foreignUuid('issued_by')->nullable()->constrained('identity.users');
            $t->string('issued_via', 16);
            $t->timestampTz('created_at')->useCurrent();
            $t->index(['analysis_id', 'created_at']);
        });
        DB::statement("ALTER TABLE evaluation.decisions ADD CONSTRAINT decisions_result_chk
            CHECK (result IN ('APPROVED','REJECTED','REVIEW_REQUIRED','INCONCLUSIVE'))");
        DB::statement("ALTER TABLE evaluation.decisions ADD CONSTRAINT decisions_via_chk
            CHECK (issued_via IN ('USER','SERVICE'))");

        Schema::create('evaluation.exceptions', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('finding_id')->constrained('evaluation.findings');
            $t->foreignUuid('requested_by')->constrained('identity.users');
            $t->foreignUuid('approver_id')->nullable()->constrained('identity.users');
            $t->string('kind', 20);
            $t->text('reason');
            $t->timestampTz('expires_at');
            $t->string('status', 16)->default('PENDING');
            $t->text('decision_note')->nullable();
            $t->timestampTz('decided_at')->nullable();
            $t->timestampTz('created_at')->useCurrent();
            $t->timestampTz('updated_at')->nullable();
            $t->index('finding_id');
            $t->index('status');
        });
        DB::statement("ALTER TABLE evaluation.exceptions ADD CONSTRAINT exceptions_status_chk
            CHECK (status IN ('PENDING','APPROVED','REJECTED','REVOKED'))");
        DB::statement("ALTER TABLE evaluation.exceptions ADD CONSTRAINT exceptions_kind_chk
            CHECK (kind IN ('FALSE_POSITIVE','ACCEPTED_RISK'))");
        DB::statement('ALTER TABLE evaluation.exceptions ADD CONSTRAINT exceptions_sod_chk
            CHECK (approver_id IS NULL OR approver_id <> requested_by)');
        DB::statement('ALTER TABLE evaluation.exceptions ADD CONSTRAINT exceptions_expiry_chk
            CHECK (expires_at > created_at)');

        Schema::create('evaluation.reports', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $t->foreignUuid('analysis_id')->constrained('evaluation.analyses');
            $t->foreignUuid('decision_id')->nullable()->constrained('evaluation.decisions');
            $t->string('format', 16);
            $t->string('uri', 512);
            $t->char('sha256', 64);
            $t->bigInteger('size_bytes');
            $t->foreignUuid('created_by')->nullable()->constrained('identity.users');
            $t->timestampTz('created_at')->useCurrent();
            $t->index('analysis_id');
        });
        DB::statement("ALTER TABLE evaluation.reports ADD CONSTRAINT reports_format_chk
            CHECK (format IN ('json','sarif','html','pdf'))");
    }

    public function down(): void
    {
        foreach (['reports', 'exceptions', 'decisions', 'recommendations', 'evidences', 'findings', 'scan_jobs', 'analyses'] as $table) {
            Schema::dropIfExists("evaluation.{$table}");
        }
    }
};
