import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Llaves} from '../config/llaves';
import {Persona} from '../models';
import {PersonaRepository} from '../repositories';
const generador = require("password-generator");
const encriptar = require("crypto-js");
const jwt = require("jsonwebtoken");

@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(
    @repository(PersonaRepository)
    public personaRepository: PersonaRepository,

  ) { }

  /*
   * Add service methods here
   */

  //metodos de generacion de contraseña
  GenerarClave() {
    let clave = generador(8, false);
    return clave;
  };

  CifrarClave(clave: string) {
    let claveCifrada = encriptar.MD5(clave).toString();
    return claveCifrada;
  }

  IdentificarPersona(usuario: string, clave: string) {
    try {
      let p = this.personaRepository.findOne({
        where: {
          correo: usuario,
          clave: clave,
        }
      });

      if (p) {
        return p;
      }
      return false;
    } catch (error) {
      return false;
    }
  };

  GenerarTokenJWT(persona: Persona) {
    let token = jwt.sign({
      data: {
        id: persona.id,
        correo: persona.correo,
        nombre: `${persona.nombre} ${persona.apellido}`
      }
    }, Llaves.claveJWT);

    return token;
  };

  ValidarTokenJWT(token: string) {
    try {

      let datos = jwt.verify(token, Llaves.claveJWT);
      return datos;
    } catch {
      return false;
    }
  };
}
