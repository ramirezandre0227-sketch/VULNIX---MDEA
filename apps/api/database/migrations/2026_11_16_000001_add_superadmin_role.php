<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Rol superadmin (unión de capacidades) y nombres de usuario con espacios internos.
 * Los nombres se guardan en minúsculas: el inicio de sesión no distingue mayúsculas.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE identity.users DROP CONSTRAINT users_role_chk');
        DB::statement("ALTER TABLE identity.users ADD CONSTRAINT users_role_chk
            CHECK (role IN ('developer','security_reviewer','approver','admin','auditor','superadmin'))");
        DB::statement('ALTER TABLE identity.users DROP CONSTRAINT users_username_chk');
        DB::statement("ALTER TABLE identity.users ADD CONSTRAINT users_username_chk
            CHECK (username ~ '^[a-z0-9._-]([a-z0-9._ -]{1,62})[a-z0-9._-]$' AND username !~ '  ')");
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE identity.users DROP CONSTRAINT users_role_chk');
        DB::statement("ALTER TABLE identity.users ADD CONSTRAINT users_role_chk
            CHECK (role IN ('developer','security_reviewer','approver','admin','auditor'))");
        DB::statement('ALTER TABLE identity.users DROP CONSTRAINT users_username_chk');
        DB::statement("ALTER TABLE identity.users ADD CONSTRAINT users_username_chk
            CHECK (username ~ '^[a-z0-9._-]{3,64}$')");
    }
};
