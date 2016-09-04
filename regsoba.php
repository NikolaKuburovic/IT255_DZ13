<?php

	header("Access-Control-Allow-Origin: *");
	header('Access-Control-Allow-Methods: GET, POST');
	header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token , Authorization, Token, token, TOKEN');

	include("functions.php");
	
	if(!empty($_POST['ime']) && !empty($_POST['sprat']) && !empty($_POST['kreveti']) && !empty($_POST['m2']) && !empty($_POST['tv']) && !empty($_POST['internet']) && !empty($_POST['djakuzi']) && !empty($_POST['rezervacija'])){
		$ime = $_POST['ime'];
		$sprat = $_POST['sprat'];
		$kreveti = $_POST['kreveti'];
		$m2 = $_POST['m2'];
		$tv = $_POST['tv'];
		$internet = $_POST['internet'];
		$djakuzi = $_POST['djakuzi'];
		$rezervacija = $_POST['rezervacija'];

		addRoom($ime, $sprat, $kreveti, $m2, $tv, $internet, $djakuzi, $rezervacija);
		
	}else{

		die();
		echo '<script type="text/javascript">

 		window.alert("Niste popunili sva polja u formi.");


 	</script>';
	}	
?>