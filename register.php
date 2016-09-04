<?php
	header("Access-Control-Allow-Origin: *");
	header('Access-Control-Allow-Methods: GET, POST');
	header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token, Authorization, Token,
		token, TOKEN');

	include("functions.php");


	if(isset($_POST['ime']) && isset($_POST['prezime']) && isset($_POST['username']) && isset($_POST['password'])){
		$ime = $_POST['ime'];
		$prezime = $_POST['prezime'];
		$username = $_POST['username'];
		$password = $_POST['password'];
		echo register($username,$password,$ime,$prezime);
		
	} else{
		echo '<script type="text/javascript">

		window.alert("Niste popunili sva polja.");

		document.location.href = "index_register.html"; 

	</script>';
	}

?>