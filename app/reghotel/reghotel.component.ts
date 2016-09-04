import { Component, Directive } from 'angular2/core';
import { FormBuilder, Validators, ControlGroup, Control, FORM_DIRECTIVES, FORM_BINDINGS} from 'angular2/common';
import { Http, HTTP_PROVIDERS, Headers } from 'angular2/http';
import 'rxjs/Rx';
import { Router, ROUTER_PROVIDERS } from 'angular2/router';

@Component({
	selector: 'RegHotel',
	templateUrl: 'app/reghotel/reghotel.html',
	directives: [FORM_DIRECTIVES],
	viewBindings: [FORM_BINDINGS]
})

export class RegHotelComponent {
	registerForm: ControlGroup;
	http: Http;
	router: Router;
	postResponse: String;

	constructor(builder: FormBuilder, http: Http, router: Router) {
		this.http = http;
		this.router = router;
		this.registerForm = builder.group({
			naziv: ["", Validators.none],
			brojSoba: ["", Validators.none],
			kategorija: ["", Validators.none],
			adresa: ["", Validators.none],
			lokacija: ["", Validators.none],
		});
				}
				
	dodajHotel(): void {

		if((this.registerForm.value.naziv === "") || (this.registerForm.value.brojSoba === "") || 
		(this.registerForm.value.kategorija === "") || (this.registerForm.value.adresa === "") || 
		(this.registerForm.value.lokacija === "")){
			alert("Niste popunili sva polja u formi!");
		}
		else{
		var data = "&naziv=" + this.registerForm.value.naziv + "&brojSoba=" + this.registerForm.value.brojSoba +
			"&kategorija=" + this.registerForm.value.kategorija + "&adresa=" + this.registerForm.value.adresa +
			"&lokacija=" + this.registerForm.value.lokacija;

		var headers = new Headers();

		headers.append('Content-Type', 'application/x-www-form-urlencoded');
		headers.append('token', localStorage.getItem('token'));

		this.http.post('http://localhost/MetHotels/reghotel.php', data, { headers: headers })
			.map(res => res)
			.subscribe(data => this.postResponse = data,
			err => alert(JSON.stringify(err)),
			() => {
				if (this.postResponse._body.indexOf("error") === -1) {
					alert("Uspesno dodavanje hotela");
					this.router.parent.navigate(['./MainPage']);
				} else {
					alert("Neuspesno dodavanje hotela");
				}
			}
			);
	}
}
}