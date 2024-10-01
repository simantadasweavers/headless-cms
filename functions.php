<?php

require('rest_functions/enqueue.php');

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


//remove_role( 'user' );
add_role('user', 'User', array(
    'read' => true,
    'create_posts' => false,
    'edit_posts' => false,
    'edit_others_posts' => false,
    'publish_posts' => false,
    'manage_categories' => false,
));


?>