<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

include __DIR__ . '/auth.php';
Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

