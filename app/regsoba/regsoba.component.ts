import { Component, Directive } from 'angular2/core';
import { FormBuilder, Validators, ControlGroup, Control, FORM_DIRECTIVES, FORM_BINDINGS} from 'angular2/common';
import { Http, HTTP_PROVIDERS, Headers } from 'angular2/http';
import 'rxjs/Rx';
import { Router, ROUTER_PROVIDERS } from 'angular2/router';

@Component({
	selector: 'RegSoba',
	templateUrl: 'app/regsoba/regsoba.html',
	directives: [FORM_DIRECTIVES],
	viewBindings: [FORM_BINDINGS]
})

export class RegSobaComponent {
	registerForm: ControlGroup;
	http: Http;
	router: Router;
	postResponse: String;

	constructor(builder: FormBuilder, http: Http, router: Router) {
		this.http = http;
		this.router = router;
		this.registerForm = builder.group({
			ime: ["", Validators.none],
			sprat: ["", Validators.none],
			kreveti: ["", Validators.none],
			m2: ["", Validators.none],
			tv: ["", Validators.none],
			internet: ["", Validators.none],
			djakuzi: ["", Validators.none],
			rezervacija: ["", Validators.none],
		});
				}

	dodajSobu(): void {
		
		if((this.registerForm.value.ime === "") || (this.registerForm.value.sprat === "") || 
		(this.registerForm.value.kreveti === "") || (this.registerForm.value.m2 === "") || 
		(this.registerForm.value.tv === "") || (this.registerForm.value.internet === "") || 
		(this.registerForm.value.djakuzi === "") || (this.registerForm.value.rezervacija === "")){
			alert("Niste popunili sva polja u formi!");
		}
		else{
		var data = "&ime=" + this.registerForm.value.ime + "&sprat=" + this.registerForm.value.sprat +
			"&kreveti=" + this.registerForm.value.kreveti + "&m2=" + this.registerForm.value.m2 +
			"&tv=" + this.registerForm.value.tv + "&internet=" + this.registerForm.value.internet +
			"&djakuzi=" + this.registerForm.value.djakuzi + "&rezervacija=" + this.registerForm.value.rezervacija;

		var headers = new Headers();

		headers.append('Content-Type', 'application/x-www-form-urlencoded');
		headers.append('token', localStorage.getItem('token'));


		this.http.post('http://localhost/MetHotels/regsoba.php', data, { headers: headers })
			.map(res => res)
			.subscribe(data => this.postResponse = data,
			err => alert(JSON.stringify(err)),
			() => {
				
				if (this.postResponse._body.indexOf("error") === -1) {
					alert("Uspesno dodavanje sobe");
					this.router.parent.navigate(['./MainPage']);
				} else {
					alert("Neuspesno dodavanje sobe");
				}
			}
			);
	}
	}
}