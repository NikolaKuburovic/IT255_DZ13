import { Component, Directive } from 'angular2/core';
import {Http, HTTP_PROVIDERS} from 'angular2/http';
import 'rxjs/Rx';
import {RouteConfig, ROUTER_DIRECTIVES } from 'angular2/router';

@Component({
  selector: 'MainPage',
  templateUrl: 'app/mainpage/mainpage.html',
  directives: [ROUTER_DIRECTIVES],
})

export class MainPageComponent {
}