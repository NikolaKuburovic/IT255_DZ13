import {Component} from 'angular2/core';
import {RouteConfig, Router, ROUTER_DIRECTIVES} from 'angular2/router';
import { MainPageComponent } from './mainpage/mainpage.component';
import { AboutUsComponent } from './aboutus/aboutus.component';
import { SobeComponent } from './sobe/sobe.component';
import { RegSobaComponent } from './regsoba/regsoba.component';
import { RegHotelComponent } from './reghotel/reghotel.component';
import { RegisterComponent } from './register/register.component';
import { LoginComponent} from './login/login.component';
import {Pipe} from 'angular2/core';
@Component({
    selector: 'moja-aplikacija',
    templateUrl: 'app/router.html',
    directives: [ROUTER_DIRECTIVES]
})
@RouteConfig([
    { path: '/', name: 'MainPage', component: MainPageComponent, useAsDefault: true },
    { path: '/aboutus', name: 'AboutUs', component: AboutUsComponent },
    { path: '/sobe', name: 'Sobe', component: SobeComponent },
    { path: '/regsoba', name: 'RegSoba', component: RegSobaComponent },
    { path: '/reghotel', name: 'RegHotel', component: RegHotelComponent },
    { path: '/register', name: 'Register', component: RegisterComponent },
    { path: '/login', name: 'Login', component: LoginComponent }
])
export class AppComponent {
    router: Router;
    isAuth: String;
    constructor(router: Router) {
        this.router = router;
        router.subscribe((val) => {
            if (localStorage.getItem('token') !== null) {
                this.isAuth = "yes";
            } else {
                this.isAuth = "no";
            }
        });
    }
    onLogout(): void {
        localStorage.removeItem("token");
        this.router.navigate(['./MainPage']);
        if (localStorage.getItem('token') !== null) {
            this.isAuth = "yes";
        } else {
            this.isAuth = "no";
        }
    }

}