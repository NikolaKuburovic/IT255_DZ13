import { Component, Directive } from 'angular2/core';
import { FormBuilder, Validators, ControlGroup, Control, FORM_DIRECTIVES, FORM_BINDINGS} from 'angular2/common';
import {Router, ROUTER_PROVIDERS, ROUTER_DIRECTIVES} from 'angular2/router';
import {Http, HTTP_PROVIDERS, Headers} from 'angular2/http';
import 'rxjs/Rx';
import {SearchPipe} from '../pipe/search';
import {SearchPipe2} from '../pipe/search2';

@Component({
  selector: 'Sobe',
  templateUrl: 'app/sobe/sobe.html',
  pipes: [SearchPipe, SearchPipe2],
  directives: [ROUTER_DIRECTIVES, FORM_DIRECTIVES],
  viewBindings: [FORM_BINDINGS]

})

export class SobeComponent {

  router: Router;
  http: Http;
  kreveti: String = "";
  m2: String = "";

  sobe: Object[];
  constructor(builder: FormBuilder, router: Router, http: Http) {
    this.router = router;
    this.http = http;

    var headers = new Headers();
    headers.append('Content-Type', 'application/x-www-form-urlencoded');
    headers.append('token', localStorage.getItem('token'));

    http.get('http://localhost/MetHotels/sobejson.php', { headers: headers })
      .map(res => res.json()).share()
      .subscribe(sobe => {
        this.sobe = sobe;
        setInterval(function () {
          $('table').DataTable();
        }, 100);
      },
      err => {
        this.router.parent.navigate(['./MainPage']);

      }
      );
  }
}