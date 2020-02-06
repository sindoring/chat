<?php

namespace App\Http\Controllers;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class Authorization extends Controller
{
    public function login(Request $request){
        $request->validate([
            'email'=>'required|string|email',
            'password'=>'required|string'
        ]);

        $credentials = request(['email','password']);

        if(!Auth::attempt($credentials)){
            return response()->json([
                'wrong data'
            ]);
        }

        $user = $request->user();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        $token->save();

        return response()->json([
            'access_token'=>$tokenResult->accessToken,
            'token_type'=>'Bearer',
            'expires_at'=>Carbon::parse($tokenResult->token->expires_at)->toDateTime()
        ]);

    }

    public function registration(Request $request){

        $request->validate([
            'name'=>'required|string',
            'email'=>'required|string|email',
            'password'=>'required|string'
        ]);

        $user = new User([
           'name'=>$request->name,
           'email'=>$request->email,
           'password'=>bcrypt($request->password)
        ]);
        $user->save();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        $token->save();

        return response()->json([
            'access_token'=>$tokenResult->accessToken,
            'token_type'=>'Bearer',
            'expires_at'=>Carbon::parse($tokenResult->token->expires_at)->toDateTime()
        ],201);
    }

    public function logout(Request $request){
        $request->user()->token()->revoke();

        return response()->json([
            'message'=>'success'
        ],200);
    }
}
