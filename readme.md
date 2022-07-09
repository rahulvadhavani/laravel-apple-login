#Step 1 (setup in apple developer console)

    =>follow all the Step from this reference until the "Generate the Client Secret" section of this doc.
    
    
    =>Document :https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple

    =>end of the all Steps you get following detail:
    
    ->APPLE_CLIENT_ID="demo.tecocraft.net"  (The Services ID from "Create a Services ID" section of this doc is used as the OAuth 'APPLE_CLIENT_ID')
    ->APPLE_REDIRECT_URI ("Return URLs" when you Configure button next to Sign In with Apple in "Create a Services ID" step)
    ->APPLE_KEY_ID (you will get this when you goto "Certificates, Identifiers & Profiles" -> "Identifiers" -> "your Services ID Identifiers")
    ->APPLE_TEAM_ID (you will get this when you goto "Certificates, Identifiers & Profiles" -> "keys" -> "key that you created in (Create a Private Key for Client Authentication) step")
    ->APPLE_PRIVATE_KEY  (That file with ".p8" exention which downloaded at the end of the step "Create a Private Key for Client Authentication")
    ->APPLE_CLIENT_SECRET (we will Configure this dynamically of every login request)


    all apple console setup is done now let's setup for the laravel server


#step 2 (setup and installation laravel packages for apple login)

    =>composer create-project laravel/laravel {app name}

    =>Install socialite package and apple provider

        #(1) composer require socialiteproviders/apple

        #(2) Add configuration to config/services.php
        -------------------------------------------
        //store the downloaded ".p8" file wth exention ".txt" in storage folder of laravel app and provde the path in "private_key"

            'apple' => [
                'client_id' => env('APPLE_CLIENT_ID'),
                'client_secret' => env('APPLE_CLIENT_SECRET'),
                'team_id' => env('APPLE_TEAM_ID'),
                'key_id' => env('APPLE_KEY_ID'),
                'private_key' => file_get_contents(storage_path('AuthKey_xyz123.txt')),
                'redirect' => env('APPLE_REDIRECT_URI')
            ],
        -------------------------------------------

        #(3) Event Listener app/Providers/EventServiceProvider.php
        -------------------------------------------
            protected $listen = [
                // ...other setup
                \SocialiteProviders\Manager\SocialiteWasCalled::class => [
                    \SocialiteProviders\Apple\AppleExtendSocialite::class.'@handle',
                ],
            ]
        -------------------------------------------

    setup for the laravel package is done now Generate the client secret on evry apple login request


#step 3 (add service for Generate client secret)

    Reference Document for this step: https://bannister.me/blog/generating-a-client-secret-for-sign-in-with-apple-on-each-request
    
    #(1) First we create a class to generate the Apple JWT token
    -------------------------------------------
        // app/Services/AppleToken.php
        
        <?php

        namespace App\Services;

        use Carbon\CarbonImmutable;
        use Exception;
        use Lcobucci\JWT\Configuration;

        class AppleToken
        {
            private Configuration $jwtConfig;

            public function __construct(Configuration $jwtConfig)
            {
                $this->jwtConfig = $jwtConfig;
            }

            public function generate()
            {
                try {

                    $now = CarbonImmutable::now();
                    $token = $this->jwtConfig->builder()
                        ->issuedBy(config('services.apple.team_id'))
                        ->issuedAt($now)
                        ->expiresAt($now->addHour())
                        ->permittedFor('https://appleid.apple.com')
                        ->relatedTo(config('services.apple.client_id'))
                        ->withHeader('kid', config('services.apple.key_id'))
                        ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());
                    return $token->toString();
                } catch (\Throwable $th) {
                    throw new Exception($th->getMessage());
                }
            }
        }

    -------------------------------------------

    #(2) The class AppleToken itself requires a configuration object, let's provide this from the AuthServiceProvider

    -------------------------------------------
        // app/Providers/AuthServiceProvider.php
    
        use App\Services\AppleToken;
        use Lcobucci\JWT\Configuration;
        use Lcobucci\JWT\Signer\Ecdsa\Sha256;
        use Lcobucci\JWT\Signer\Key\InMemory;
        
        public function boot()
        {
            // ...other bindings or setup
        
            $this->app->bind(Configuration::class, fn () => Configuration::forSymmetricSigner(
                Sha256::create(),
                InMemory::plainText(config('services.apple.private_key')),
            ));
        }
    ------------------------------------------- 
    // All setup is done now let's code for the apple Authentication


#step 4 (code for sign with apple for webside)
    // # I used laravel ui package for handle Authentication flow

    #(1) Add web routes
    -------------------------------------------
        // routes/web.php
        use App\Http\Controllers\SocialAuthController;

        Route::controller(SocialAuthController::class)->group(function () {
            Route::post('apple-redirect', 'handleCallback');
            Route::get('apple-login', 'appleLogin')->name('apple.login');
        });

    -------------------------------------------

    #(2) Add controller
    -------------------------------------------
        // app/Http/Controllers/SocialAuthController.php
        
        <?php

        namespace App\Http\Controllers;

        use App\Models\User;
        use Illuminate\Http\Request;
        use Laravel\Socialite\Facades\Socialite;
        use App\Services\AppleToken;
        use Illuminate\Support\Facades\Auth;
        use Illuminate\Support\Facades\Hash;
        use Illuminate\Support\Facades\Log;

        class SocialAuthController extends Controller
        {
            // Handle  Apple callback and Authentication here
            public function handleCallback(AppleToken $appleToken)
            {
                try {
                    $provider = 'apple';
                    config()->set('services.apple.client_secret', $appleToken->generate());
                    $socialUser = Socialite::driver($provider)
                        ->stateless()
                        ->user();
                    Log::info('socialUser');
                    Log::info(print_r($socialUser, true));
                    Log::info(config('services.apple.client_secret'));

                    // handle login integration from here
                    $user =  User::where(['provider_id' => $socialUser->getId()])->first();
                    Log::info('user');
                    Log::info(print_r($user, true));

                    if ($user) {
                        Auth::login($user);
                        $user->update(['email' => $socialUser->getEmail()]);
                        return redirect('/home');
                    } else {
                        $user = User::create([
                            'name'          => $socialUser->getName() == null ? strtok($socialUser->getEmail(), '@') : $socialUser->getName(),
                            'email'         => $socialUser->getEmail(),
                            'password'      => Hash::make('12345678'),
                            'provider_id'   => $socialUser->getId(),
                            'provider'      => User::APPLEPROVIDER,
                        ]);
                        Auth::login($user);
                        return redirect()->route('home');
                    }
                    //end handle login integration from here
                } catch (\Throwable $th) {
                    Log::info('error');
                    Log::info($th->getMessage());
                }
            }

            // redirect user to apple login page
            public function appleLogin(Request $request, AppleToken $appleToken)
            {
                try {
                    $appleToken = $appleToken->generate();
                    return Socialite::driver('apple')->redirect();
                } catch (\Throwable $th) {
                    return redirect()->back()->with('error', $th->getMessage());
                }
            }
        }

    -------------------------------------------

    #(1) update login Blade file

    -------------------------------------------
        // resources/views/auth/login.blade.php
        // add this code next to the login button for show apple login button

        <div class="row mt-3">
            <div class="col-md-6 offset-md-4">
                <a class="btn btn-dark" href="{{ route('apple.login') }}">
                    {{ __('Sign in With Apple') }}
                </a>
            </div>
        </div>

    -------------------------------------------

#step 5 (code for sign with apple for API)
    // # I used here laravel passport package for handle Authentication flow
    
    #(1) Add API routes
    -------------------------------------------
        // routes/api.php
        use App\Http\Controllers\Api\ProductController;
        use App\Http\Controllers\Api\AuthController;

        Route::post('apple-login',[AuthController::class,'appleLogin'])
        
        Route::middleware('auth:api')->group( function () {
            Route::resource('products', ProductController::class);
            Route::get('logout', [AuthController::class,'logout']);
        });

    -------------------------------------------

    #(2) Add controllers (AuthController and ProductController) 
    -------------------------------------------
        // #1 app/Http/Controllers/Api/AuthController.php

        <?php

        namespace App\Http\Controllers\Api;

        use App\Http\Controllers\Controller;
        use Illuminate\Http\Request;
        use App\Models\User;
        use App\Services\AppleToken;
        use Illuminate\Support\Facades\Auth;
        use Illuminate\Support\Facades\Hash;
        use Illuminate\Support\Facades\Log;
        use Illuminate\Support\Facades\Validator;
        use Laravel\Socialite\Facades\Socialite;

        class AuthController extends Controller
        {
        
            public function logout(Request $request)
            {
                try {
                    $request->user()->token()->revoke();
                    return response()->json(['status' => true, 'message' => 'Successfully logged out']);
                } catch (\Throwable $th) {
                    return response()->json(['status' => false, 'message' => $th->getMessage()], 200);
                }
            }

            public function appleLogin(Request $request, AppleToken $appleToken)
            {

                try {
                    $validator = Validator::make($request->all(), [
                        'name' => 'required|max:70',
                        'token' => 'required',
                    ]);

                    if ($validator->fails()) {
                        return response()->json(['status' => false, 'message' => $validator->messages()->first(), 'errors' => $validator->errors(),], 200);
                    }

                    config()->set('services.apple.client_secret', $appleToken->generate());
                    $socialUser = Socialite::driver('apple')->userFromToken($request->token);
                    Log::info('socialUser');
                    Log::info(print_r($socialUser, true));
                    Log::info(config('services.apple.client_secret'));

                    // handle login integration from here
                    $user =  User::where(['provider_id' => $socialUser->getId()])->first();
                    Log::info('user');
                    Log::info(print_r($user, true));

                    if ($user) {
                        $user->update(['email' => $socialUser->getEmail()]);
                    } else {
                        $user = User::create([
                            'name'          => $request->name,
                            'email'         => $socialUser->getEmail(),
                            'password'      => Hash::make('12345678'),
                            'provider_id'   => $socialUser->getId(),
                            'provider'      => User::APPLEPROVIDER,
                        ]);
                    }
                    $data['token'] =  $user->createToken(config('app.name'))->accessToken;
                    $data['name'] =  $user->name;
                    $data['email'] =  $user->email;
                    return response()->json(['status' => true, 'message' => 'Login successfully', 'data' => $data], 200);
                } catch (\Throwable $th) {
                    return response()->json(['status' => false, 'message' => $th->getMessage()], 200);
                }
            }
        }


        // #2 app/Http/Controllers/Api/ProductController.php

        <?php

        namespace App\Http\Controllers\Api;

        use App\Http\Controllers\Controller;
        use Illuminate\Http\Request;

        class ProductController extends Controller
        {
            public function index(){ //dummy data for test api
                $data = [
                    [
                        'id' => 1,
                        'name' => 'dummy1',
                        'price' => '500'
                    ],
                    [
                        'id' => 1,
                        'name' => 'dummy2',
                        'price' => '800'
                    ]
                ];
                return response()->json(['status' => true, 'message' => 'success', 'data' => $data], 200);
            }
        }

    -------------------------------------------
    
#step 6 (bypass csrf token and test the web and api functionality)
    
    #(1) Add 'apple-redirect' route in except parameter
    -------------------------------------------
        // App/Http/Middleware/VerifyCsrfToken.php;

        protected $except = [
            'apple-redirect'
        ];
    -------------------------------------------

    #(2) Test the apple login
    -------------------------------------------
        =>click on login with apple button from login page and check login is working or not if not then cross check the configuration

        =>now for api pass name and token parameter in post method call of apple-login and check the api login
        (### you get this token from app side but for testing you can use the "id_token" from response of SocialAuthController@handleCallback  we added log here)
        
        ex.
        Log::info('socialUser');
        Log::info(print_r($socialUser, true));

    -------------------------------------------

