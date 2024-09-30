<?php 
// registering custom routes
add_action('rest_api_init', function () {
    register_rest_route('rest-apis/v1', '/auth/', array(
        'methods' => 'POST',
        'callback' => 'register_user_func',
        'permission_callback' => '__return_true', // Use for bypassing permissions for now
        'args' => validate_register_user_arguments(),
    ));
});
function validate_register_user_arguments()
{
    $args = array();

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

    return $args;
}
function register_user_func($request)
{
    $return_arr = $request->get_params();

    //  getting arguments value from api endpoints and sanitize it
    $email = isset($return_arr['email']) ? sanitize_email($return_arr['email']) : '';


    $response_message = "user registered successfully";
    return new WP_REST_Response(
        array(
            'status' => 200,
            'message' => $response_message,
            'data' => $email
        )
    );

}

?>