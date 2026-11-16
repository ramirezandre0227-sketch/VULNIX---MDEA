<?php

namespace Tests;

use App\Enums\Role;
use App\Models\Analysis;
use App\Models\Analyzer;
use App\Models\Policy;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Services\Ingest\ArtifactIngestor;
use App\Services\Policy\PolicyLoader;
use App\Services\Signing\DecisionSigner;
use App\Support\DataStore;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use ZipArchive;

abstract class TestCase extends BaseTestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // Almacén aislado por test, fuera de carpetas sincronizadas (OneDrive bloquea ficheros durante la sincronización).
        $base = str_replace('\\', '/', sys_get_temp_dir()).'/vulnix-tests';
        config([
            'vulnix.data_dir' => $base.'/data-'.Str::lower(Str::random(12)),
            'vulnix.keys_dir' => $base.'/keys-'.getmypid(),
        ]);
        foreach ([config('vulnix.data_dir'), config('vulnix.keys_dir')] as $dir) {
            if (! is_dir($dir)) {
                mkdir($dir, 0700, true);
            }
        }
        $signer = app(DecisionSigner::class);
        if (! $signer->hasKeys()) {
            $signer->generateKeys();
        }
    }

    protected function tearDown(): void
    {
        $dir = config('vulnix.data_dir');
        parent::tearDown();
        if (is_string($dir) && str_contains($dir, '/vulnix-tests/data-') && is_dir($dir)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $file) {
                @chmod($file->getPathname(), 0700); // los ficheros inmutables son de solo lectura
                $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
            }
            @rmdir($dir);
        }
    }

    protected function user(Role $role, ?string $username = null): User
    {
        return User::create([
            'username' => $username ?? strtolower($role->value).'-'.Str::lower(Str::random(6)),
            'display_name' => $role->label(),
            'role' => $role->value,
            'password_hash' => 'Correct-Horse-9-Battery',
            'active' => true,
        ]);
    }

    /** Carga una política del repositorio (o YAML propio) como ACTIVA, aprobada por un aprobador distinto. */
    protected function activePolicy(string $codeOrYaml = 'web-development'): Policy
    {
        $yaml = str_contains($codeOrYaml, "\n") ? $codeOrYaml
            : file_get_contents(config('vulnix.policies_dir')."/{$codeOrYaml}.yaml");
        $parsed = app(PolicyLoader::class)->fromYaml($yaml);
        $existing = Policy::where('code', $parsed['code'])->where('version', $parsed['version'])->first();
        if ($existing) {
            return $existing;
        }
        $policy = Policy::create([
            'code' => $parsed['code'], 'version' => $parsed['version'], 'rules_json' => $parsed['rules'],
            'sha256' => $parsed['sha256'], 'source_yaml' => $parsed['source'], 'status' => 'DRAFT',
            'created_by' => $this->user(Role::SecurityReviewer)->id,
        ]);
        Policy::where('code', $policy->code)->where('status', 'ACTIVE')->update(['status' => 'RETIRED']);
        $policy->forceFill(['status' => 'ACTIVE', 'approved_by' => $this->user(Role::Approver)->id, 'approved_at' => now()])->save();

        return $policy;
    }

    protected function zipUpload(array $files, string $name = 'app.zip'): UploadedFile
    {
        $path = tempnam(sys_get_temp_dir(), 'vxz');
        $zip = new ZipArchive;
        $zip->open($path, ZipArchive::OVERWRITE);
        foreach ($files as $entry => $content) {
            $zip->addFromString($entry, $content);
        }
        $zip->close();

        return new UploadedFile($path, $name, 'application/zip', null, true);
    }

    protected function project(User $owner, string $profile = 'web-development'): Project
    {
        return Project::create([
            'name' => 'Proyecto '.Str::random(5), 'slug' => 'p-'.Str::lower(Str::random(10)),
            'owner_id' => $owner->id, 'criticality' => 'HIGH', 'default_profile' => $profile,
        ]);
    }

    protected function version(User $owner, ?Project $project = null, array $files = ['index.php' => "<?php echo 'hola';\n"]): ProjectVersion
    {
        $project ??= $this->project($owner);

        return app(ArtifactIngestor::class)->ingest($project, $owner, $this->zipUpload($files), '1.0.'.random_int(0, 99999));
    }

    /** Simula al orquestador: completa los jobs con evidencia íntegra y deja el análisis en EVALUATING. */
    protected function completeJobs(Analysis $analysis, array $overrides = [], array $metadata = []): void
    {
        $store = app(DataStore::class);
        foreach ($analysis->jobs()->get() as $job) {
            $status = $overrides[$job->analyzer_name] ?? 'SUCCEEDED';
            $analyzer = Analyzer::query()->firstOrCreate(
                ['name' => $job->analyzer_name, 'version' => '1.0.0', 'config_hash' => str_repeat('c', 64)],
                ['category' => $job->category, 'healthy' => true, 'metadata' => []],
            );
            DB::table('evaluation.scan_jobs')->where('id', $job->id)->update(['status' => 'RUNNING', 'started_at' => now()]);
            $meta = $metadata[$job->analyzer_name] ?? match ($job->category) {
                'quality' => ['build' => ['executed' => true, 'passed' => true], 'tests' => ['executed' => false, 'passed' => null], 'coverage' => ['line_pct' => null]],
                'sca' => ['components' => 0, 'intel' => ['ecosystems' => []]],
                default => [],
            };
            DB::table('evaluation.scan_jobs')->where('id', $job->id)->update([
                'status' => $status, 'ended_at' => now(), 'exit_code' => $status === 'SUCCEEDED' ? 0 : 1,
                'analyzer_id' => $analyzer->id, 'metadata' => json_encode($meta),
                'error_type' => $status === 'SUCCEEDED' ? null : 'TOOL_ERROR',
            ]);
            if ($status === 'SUCCEEDED') {
                $ev = $store->putImmutable("evidence/{$analysis->id}/{$job->id}/report.json", json_encode(['job' => $job->id, 'findings' => []]));
                DB::table('evaluation.evidences')->insert([
                    'id' => (string) Str::uuid(), 'job_id' => $job->id, 'kind' => 'RAW_OUTPUT', 'uri' => $ev['uri'],
                    'sha256' => $ev['sha256'], 'size_bytes' => $ev['size'], 'created_at' => now(),
                ]);
            }
        }
        foreach (['RUNNING', 'NORMALIZING', 'EVALUATING'] as $s) {
            DB::table('evaluation.analyses')->where('id', $analysis->id)->update(['status' => $s]);
        }
        $analysis->refresh();
    }

    protected function addFinding(Analysis $analysis, string $category, string $severity, string $confidence, array $extra = []): string
    {
        $job = $analysis->jobs()->where('category', $category)->firstOrFail();
        $id = (string) Str::uuid();
        DB::table('evaluation.findings')->insert(array_merge([
            'id' => $id, 'analysis_id' => $analysis->id, 'job_id' => $job->id,
            'fingerprint' => 'sha256:'.hash('sha256', $id), 'rule_id' => "{$category}.test-rule", 'analyzer_name' => $job->analyzer_name,
            'category' => $category, 'title' => 'Hallazgo de prueba', 'description' => 'desc', 'severity' => $severity,
            'confidence' => $confidence, 'file_path' => 'src/a.php', 'start_line' => random_int(1, 9999), 'cwe' => 'CWE-89',
            'metadata' => '{}', 'created_at' => now(),
        ], $extra));

        return $id;
    }
}
