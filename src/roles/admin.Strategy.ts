import {AuthenticationStrategy} from '@loopback/authentication';
import {service} from '@loopback/core/dist/service';

import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {AutenticacionService} from '../services';

export class RolAdministrador implements AuthenticationStrategy {
  name: string = 'admin';

  constructor(
    @service(AutenticacionService)
    public autenticationService: AutenticacionService,
  ) { }


  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let datos = this.autenticationService.ValidarTokenJWT(token)
      if (datos) {
        let perfil: UserProfile = Object.assign({
          rol: datos.data.rol
        });
        return perfil;
        /*if (datos.data == "admin") {

        } */
      } else {
        throw new HttpErrors[401]("Token Inválido");
      }
    } else {
      throw new HttpErrors[401]("No hay Token en la autorizacion");
    }
  }
}
