<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ReportController extends Controller
{
    public function show(Request $request)
    {
        $order = $request->input('order');
        return DB::select("SELECT * FROM reports ORDER BY $order");
    }
}
