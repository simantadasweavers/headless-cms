<?php
require('vendor/autoload.php');
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * JWT_SECRET_KEY = constant define under wp-config.php
 */


// registering custom routes: auth/account
add_action('rest_api_init', function () {
    register_rest_route('rest-apis/v1', 'account/register/', array(
        'methods' => 'POST',
        'callback' => 'register_user_func',
        'permission_callback' => '__return_true', // Use for bypassing permissions for now
        'args' => validate_register_user_arguments(),
    ));
    register_rest_route('rest-apis/v1', 'account/login/', array(
        'methods' => 'POST',
        'callback' => 'login_user_func',
        'permission_callback' => '__return_true', // Use for bypassing permissions for now
        'args' => validate_login_user_arguments(),
    ));
    register_rest_route('rest-apis/v1', 'account/update/', array(
        'methods' => 'PUT',
        'callback' => 'update_user_func',
        'permission_callback' => 'jwt_auth_permission_callback',
        'args' => validate_update_user_arguments(),
    ));
    register_rest_route('rest-apis/v1', 'account/delete/', array(
        'methods' => 'DELETE',
        'callback' => 'delete_user_func',
        'permission_callback' => '__return_true', // Use for bypassing permissions for now
        'args' => validate_delete_user_arguments(),
    ));
});

function jwt_auth_permission_callback($request) {
    $auth_header = $request->get_header('Authorization');

    if (!$auth_header || strpos($auth_header, 'Bearer ') !== 0) {
        return new WP_Error('jwt_auth_no_token', 'Missing JWT token', array('status' => 403));
    }

    $token = str_replace('Bearer ', '', $auth_header);
 

    try {
        $decoded = JWT::decode($token, JWT_AUTH_SECRET_KEY, array('HS256'));

        if ($decoded && isset($decoded->data->user_id)) {
            // Validate the user ID in the token and grant permission
            $user = get_user_by('id', $decoded->data->user_id);
            if ($user) {
                return true;
            }
        }
    } catch (Exception $e) {
        return new WP_Error('jwt_auth_invalid_token', $e->getMessage(), array('status' => 403));
    }

    return new WP_Error('jwt_auth_invalid_permission', 'Invalid token or user', array('status' => 403));
}


function validate_register_user_arguments()
{
    $args = array();

    $args['first_name'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );

    $args['last_name'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );

    $args['email'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
        'validate_callback' => function ($param, $request, $key) {
            // Direct email validation using WordPress's is_email function
            if (!is_email($param)) {
                return new WP_Error('invalid_email', 'The provided email is not valid.', array('status' => 400));
            }
            return true;
        },
    );

    $args['username'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );

    $args['password'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );

    return $args;
}
function register_user_func($request)
{
    $return_arr = $request->get_params();

    //  getting arguments value from api endpoints and sanitize it
    $first_name = isset($return_arr['first_name']) ? sanitize_text_field($return_arr['first_name']) : '';
    $last_name = isset($return_arr['last_name']) ? sanitize_text_field($return_arr['last_name']) : '';
    $email = isset($return_arr['email']) ? sanitize_email($return_arr['email']) : '';
    $username = isset($return_arr['username']) ? sanitize_text_field($return_arr['username']) : '';
    $password = isset($return_arr['password']) ? sanitize_text_field($return_arr['password']) : '';


    if (email_exists($email)) {
        $return_arr = array('first_name' => $first_name, 'last_name' => $last_name, 'email' => $email, 'username' => $username, 'password' => $password);

        $response_message = "user email exists already";
        return new WP_REST_Response(
            array(
                'status' => 409,
                'message' => $response_message,
                'data' => $return_arr
            ),
            409
        );
    } else {

        if (username_exists($username)) {
            $return_arr = array('first_name' => $first_name, 'last_name' => $last_name, 'email' => $email, 'username' => $username, 'password' => $password);

            $response_message = "username exists already";
            return new WP_REST_Response(
                array(
                    'status' => 409,
                    'message' => $response_message,
                    'data' => $return_arr
                ),
                409
            );
        } else {

            $userdata = array(
                'user_nicename' => $first_name,
                'nickname' => $first_name,
                'user_email' => $email,
                'user_pass' => $password,
                'first_name' => $first_name,
                'last_name' => $last_name,
                'display_name' => $first_name . " " . $last_name,
                'user_login' => $username,
                'role' => 'user',
            );
            $user_id = wp_insert_user($userdata);

             // Current time
             $now = time();
             // Set 'exp' to 2 days from now
             $two_days_from_now = $now + (2 * 86400);  // 86400 seconds in a day
 
             $payload = [
                 'iat' => $now,  // issued at: current time
                 'exp' => $two_days_from_now,  // expiration: 2 days from now
                 'email' => $email,
                 'user_id' => $user_id,
                 'token_type' => 'access',
             ];
             $access_jwt = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');
 
 
             // Set 'exp' to 30 days from now
             $thirty_days_from_now = $now + (30 * 86400);  // 86400 seconds in a day
             $payload = [
                 'iat' => $now,  // issued at: current time
                 'exp' => $thirty_days_from_now,  // expiration: 30 days from now
                 'email' => $email,
                 'user_id' => $user_id,
                 'token_type' => 'refresh',
             ];
             $refresh_jwt = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');

             $return_arr = array('id' => $user_id, 'first_name' => $first_name, 'last_name' => $last_name, 'email' => $email, 'username' => $username, 'password' => $password, 'access_token' => $access_jwt, 'refresh_token' => $refresh_jwt);

            return new WP_REST_Response(
                array(
                    'status' => 200,
                    'message' => "user registered successfully",
                    'data' => $return_arr
                ),
                200
            );
        }

    }
}


// login user arguments validation check.
function validate_login_user_arguments()
{
    $args = array();

    $args['username'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );

    $args['password'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );

    return $args;
}
// login user functionality check.
function login_user_func($request)
{
    $return_arr = $request->get_params();

    $username = isset($return_arr['username']) ? sanitize_text_field($return_arr['username']) : '';
    $password = isset($return_arr['password']) ? sanitize_text_field($return_arr['password']) : '';

    $user = wp_authenticate($username, $password);

    if (!is_wp_error($user)) {


        // set expiration within 2 days
        $now = time();
        $two_days_from_now = $now + (2 * 86400);
        $payload = [
            'iat' => $now,
            'exp' => $two_days_from_now,
            'email' => $user->user_email,
            'token_type' => 'access',
            'user_id' => $user->ID,
        ];
        $access_jwt = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');

        // Set 'exp' to 30 days from now
        $thirty_days_from_now = $now + (30 * 86400);
        $payload = [
            'iat' => $now,
            'exp' => $thirty_days_from_now,
            'email' => $user->user_email,
            'token_type' => 'refresh',
            'user_id' => $user->ID,
        ];
        $refresh_jwt = JWT::encode($payload, JWT_SECRET_KEY, 'HS256');

        $user = array('name' => $user->display_name, 'email' => $user->user_email);
        // Successful login
        return new WP_REST_Response(
            array(
                'status' => 200,
                'message' => "login successful",
                'user' => $user,
                'access_token' => $access_jwt,
                'refresh_token' => $refresh_jwt,
            ),
            200
        );
    } else {
        // Get error message only
        // $error_message = $user->get_error_message();

        // return error codes - 'invalid_username', 'invalid_email', 'incorrect_password'
        $error_code = $user->get_error_code();

        switch ($error_code) {
            case "invalid_username":
                $error_message = "username is incorrect";
                break;
            case "invalid_email":
                $error_message = "Email id is invalid";
                break;
            case "incorrect_password":
                $error_message = "Password is invalid";
                break;
        }

        return new WP_REST_Response(
            array(
                'status' => 403,
                'message' => $error_message,
            ),
            403
        );
    }
}


// delete user arguments validation check.
function validate_delete_user_arguments()
{
    $args = array();
    $args['id'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );
    $args['token'] = array(
        'type' => 'string',
        'required' => true,
        'description' => 'this field is required',
    );
    return $args;
}
// delete user functionality check.
function delete_user_func($request)
{
    $return_arr = $request->get_params();
    $id = isset($return_arr['id']) ? sanitize_text_field($return_arr['id']) : '';
    $token = isset($return_arr['token']) ? sanitize_text_field($return_arr['token']) : '';

    try {
        JWT::decode($token, new Key(JWT_SECRET_KEY, 'HS256'));

        if (get_userdata($id)) {
            global $wpdb;
            $user_id = $id;

            // Delete User metadata
            $wpdb->delete($wpdb->usermeta, ['user_id' => $user_id], ['%d']);

            // Delete User
            $wpdb->delete($wpdb->users, ['ID' => $user_id], ['%d']);

            return new WP_REST_Response(
                array(
                    'status' => 200,
                    'message' => 'account deleted',
                ),
                200
            );
        } else {
            return new WP_REST_Response(
                array(
                    'status' => 401,
                    'message' => 'user id is invalid',
                ),
                401
            );
        }
    } catch (Exception $e) {
        return new WP_REST_Response(
            array(
                'status' => 401,
                'message' => $e->getMessage(),
            ),
            401
        );
    }
}


// update user arguments validation check.
function validate_update_user_arguments()
{
    $args = array();

    $args['first_name'] = array(
        'type' => 'string',
        'required' => false,
    );

    $args['last_name'] = array(
        'type' => 'string',
        'required' => false,
    );

    $args['email'] = array(
        'type' => 'string',
        'required' => false,
        'validate_callback' => function ($param, $request, $key) {
            // Direct email validation using WordPress's is_email function
            if (!is_email($param)) {
                return new WP_Error('invalid_email', 'The provided email is not valid.', array('status' => 400));
            }
            return true;
        },
    );

    $args['username'] = array(
        'type' => 'string',
        'required' => false,
    );
    return $args;
}
// update user functionality check.
function update_user_func($request)
{
    $return_arr = $request->get_params();

    //  getting arguments value from api endpoints and sanitize it
    $first_name = isset($return_arr['first_name']) ? sanitize_text_field($return_arr['first_name']) : '';
    $last_name = isset($return_arr['last_name']) ? sanitize_text_field($return_arr['last_name']) : '';
    $email = isset($return_arr['email']) ? sanitize_email($return_arr['email']) : '';
    $username = isset($return_arr['username']) ? sanitize_text_field($return_arr['username']) : '';
    
    if($first_name){
        // wp_update_user(array('ID' => ));

        return new WP_REST_Response(
            array(
                'status' => 201,
                'message' => "first name",
            ),
            201
        );
    }
    if($last_name){
        return new WP_REST_Response(
            array(
                'status' => 201,
                'message' => "last name",
            ),
            201
        );
    }
    if($username){
        return new WP_REST_Response(
            array(
                'status' => 201,
                'message' => "user name",
            ),
            201
        );
    }
    if($email){
        return new WP_REST_Response(
            array(
                'status' => 201,
                'message' => "email",
            ),
            201
        );
    }

}

?>