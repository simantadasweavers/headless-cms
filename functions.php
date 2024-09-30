<?php

require('rest_apis_functions.php');

// REST API access restrictions for users.
//add_filter( 'rest_authentication_errors', 'rudr_turn_off_rest_api_not_logged_in' );
function rudr_turn_off_rest_api_not_logged_in($errors)
{

    // if there is already an error, just return it
    if (is_wp_error($errors)) {
        return $errors;
    }

    if (!is_user_logged_in()) {
        // return WP_Error object if user is not logged in
        return new WP_Error('no_rest_api_sorry', 'You are not authenticated!', array('status' => 401));
    }

    // disable REST API for everyone except administrators
    // if( ! current_user_can( 'administrator' ) ) { 
    //     return new WP_Error( 'no_rest_api_sorry', 'REST API not allowed, only for admins!', array( 'status' => 401 ) );
    // }

    return $errors;
}



add_action('rest_api_init', 'wk_register_user_routes');

function wk_register_user_routes()
{
    register_rest_route(
        'wp/v2',
        '/customers',
        array(
            array(
                'methods' => 'POST',
                'callback' => 'wk_create_user_callback',
            ),
            'permission_callback' => '__return_true', // Update permission as needed
        )
    );

    register_rest_route(
        'wp/v2',
        '/customers/(?P<id>\d+)',
        array(
            array(
                'methods' => 'GET',
                'callback' => 'wk_get_user_callback',
            ),
            array(
                'methods' => 'PUT',
                'callback' => 'wk_update_user_callback',
            ),
            array(
                'methods' => 'PATCH',
                'callback' => 'wk_patch_user_callback',
            ),
            array(
                'methods' => 'DELETE',
                'callback' => 'wk_delete_user_callback',
            ),
            'permission_callback' => '__return_true', // Update permission as needed
        )
    );
}

// Create a new user
function wk_create_user_callback($request)
{
    $data = $request->get_json_params();

    // Validate and create user
    $userdata = array(
        'user_login' => $data['username'],
        'user_pass' => $data['password'],
        'user_email' => $data['email'],
        'display_name' => $data['display_name'],
        // Add other fields as necessary
    );

    $user_id = wp_insert_user($userdata);

    if (is_wp_error($user_id)) {
        return $user_id; // Return error if user creation fails
    }

    return rest_ensure_response($user_id);
}

// Find user by ID
function wk_get_user_callback($request)
{
    $id = $request['id'];
    $user = get_userdata($id);

    if (!$user) {
        return new WP_Error('no_user', 'User not found', array('status' => 404));
    }

    return rest_ensure_response($user);
}

// Update user (replace entire user data)
function wk_update_user_callback($request)
{
    $id = $request['id'];
    $data = $request->get_json_params();

    $userdata = array(
        'ID' => $id,
        'user_login' => $data['username'],
        'user_email' => $data['email'],
        'display_name' => $data['display_name'],
        // Add other fields as necessary
    );

    $updated_user_id = wp_update_user($userdata);

    if (is_wp_error($updated_user_id)) {
        return $updated_user_id; // Return error if update fails
    }

    return rest_ensure_response($updated_user_id);
}

// Patch user (update specific fields)
function wk_patch_user_callback($request)
{
    $id = $request['id'];
    $data = $request->get_json_params();

    $userdata = array('ID' => $id);
    if (isset($data['username'])) {
        $userdata['user_login'] = $data['username'];
    }
    if (isset($data['email'])) {
        $userdata['user_email'] = $data['email'];
    }
    if (isset($data['display_name'])) {
        $userdata['display_name'] = $data['display_name'];
    }
    // Add other fields as necessary

    $updated_user_id = wp_update_user($userdata);

    if (is_wp_error($updated_user_id)) {
        return $updated_user_id; // Return error if update fails
    }

    return rest_ensure_response($updated_user_id);
}

// Delete user
function wk_delete_user_callback($request)
{
    $id = $request['id'];

    if (!username_exists($id)) {
        return new WP_Error('no_user', 'User not found', array('status' => 404));
    }

    $deleted = wp_delete_user($id);

    if (!$deleted) {
        return new WP_Error('delete_failed', 'User could not be deleted', array('status' => 500));
    }

    return rest_ensure_response(array('deleted' => true));
}






?>