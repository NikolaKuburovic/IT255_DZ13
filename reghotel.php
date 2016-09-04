<?php 
	
	header("Access-Control-Allow-Origin: *");
	header('Access-Control-Allow-Methods: GET, POST');
	header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token , Authorization, Token, token, TOKEN');

	include("functions.php");
	
	if(!empty($_POST['naziv']) && !empty($_POST['brojSoba']) && !empty($_POST['kategorija']) && !empty($_POST['adresa']) && !empty($_POST['lokacija'])){
		$naziv = $_POST['naziv'];
		$brojSoba = $_POST['brojSoba'];
		$kategorija = $_POST['kategorija'];
		$adresa = $_POST['adresa'];
		$lokacija = $_POST['lokacija'];

		addHotel($naziv, $brojSoba, $kategorija, $adresa, $lokacija);
		
	}else{
		die();
		echo '<script type="text/javascript">

 		window.alert("Niste popunili sva polja u formi.");

 		</script>';
	}
?>