# ASLENS

Herramienta para realizar el análisis del Esquema Nacional de Seguridad en python para entornos linux

## Descripción

Herramienta para poder realizar el análisis del esquema nacional de seguridad (ENS), realizado por el CCN, para entornos Linux, generando el HTML del resultado.
Así mismo, permite la lectura de ficheros externos para cargar otras configuraciones además de la que incluye la propia herramienta,
la posibilidad de especificar el nivel de seguridad a aplicar o la exportación en PDF del resultado.

## Características

- Realizar un análisis del sistema
- Seleccionar el nivel de seguridad sobre el que realizar el análisis
- Cargar configuraciones para poder modificar ciertos parámetros del análisis
- Cargar configuraciones adicionales para poder incluir en el análisis
- Exportación en PDF del resultado

## Uso básico y Modo de ejecución

```python

pip install -r requirements.txt  # Opcional, solo para al exportación en PDF - Python 2.7.x
pip3 install -r requirements.txt  # Opcional, solo para al exportación en PDF - Python 2.7.x

# Uso con nivel de seguridad bajo
sudo python3 ens.py "nombre_usuario" "empresa"  # Nombre del usuario y empresa, parámetros obligatorios

# Uso con nivel de seguridad alto
sudo python3 ens.py "nombre_usuario" "empresa" -ns "alto"

# Uso con nivel alto y fichero de configuración externo y pdf
sudo python3 ens.py "Raúl Leal" "Organización" -ns alto -p -ce "data/extra_config.json"
```

## Documentación de desarrollo

La documentación del desarrollo, puede ser consultada en el PDF que se encuentra en el proyecto, más específicamente en la parte de Anexos.
[Documentación]()

## Arquitectura

Python 2.7.14 / 3.x
weasyprint 0.42
beautifulsoup4 4.8.0

## Preparación del entorno

Los requisitos para la preparación del entorno o la ejecución del mismo, son los recogidos anteriormente en el apartado de Arquitectura.
Requirements compatibles para la versión 2.7.x y 3.x.