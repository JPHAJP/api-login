# ⚡ Guía Rápida: Sistema de Encriptación de Fotografías

## 🎯 ¿Qué hace este sistema?

Todas las fotografías de identificación que se guardan en `data/identificaciones` ahora se **encriptan automáticamente** usando la clave `DATABASE_ENCRYPTION_KEY` del archivo `.env`.

## 🚀 Uso Inmediato

### ✅ Ya está funcionando

El sistema ya está activo. Las nuevas fotografías que se suban se encriptarán automáticamente.

### 📸 Si tienes fotografías antiguas

Si ya tienes fotografías en `data/identificaciones` que NO están encriptadas, ejecuta:

```bash
# 1. Primero, prueba en seco (recomendado)
python encrypt_existing_photos.py --dry-run

# 2. Encripta con backup automático
python encrypt_existing_photos.py
```

Esto encriptará las fotos existentes y creará un backup en `data/identificaciones_backup_FECHA/`

## 🧪 Verificar que funciona

```bash
# Ejecutar pruebas
python test_encryption.py
```

Deberías ver: `🎉 ¡Todas las pruebas pasaron exitosamente!`

## 🔍 Verificación Visual

1. **Antes del cambio**: Los archivos en `data/identificaciones/` se podían abrir con un visor de imágenes
2. **Después del cambio**: Los archivos están encriptados y NO se pueden abrir directamente
3. **En la aplicación**: Los admins pueden ver las fotos normalmente a través de la API

## ⚠️ IMPORTANTE

### Guarda la clave de encriptación

La clave `DATABASE_ENCRYPTION_KEY` en tu `.env` es **crítica**:

```properties
DATABASE_ENCRYPTION_KEY=a14f6764253d3}668+79f0c088bc5*511b1d}00f6f0bb72fe-999571f71db1bdb8a
```

**Si pierdes esta clave, NO podrás recuperar las fotografías encriptadas.**

Recomendaciones:
- ✅ Haz backup de esta clave en un lugar seguro (fuera del código)
- ✅ Considera usar un gestor de secretos en producción (AWS Secrets Manager, Azure Key Vault, etc.)
- ✅ No la compartas en repositorios públicos (ya está en .gitignore)

## 📁 Archivos Importantes

- `utils/file_encryption.py` - Módulo de encriptación
- `encrypt_existing_photos.py` - Script de migración
- `test_encryption.py` - Pruebas del sistema
- `PHOTO_ENCRYPTION.md` - Documentación completa
- `ENCRYPTION_SUMMARY.md` - Resumen de implementación

## 🆘 Problemas Comunes

### "DATABASE_ENCRYPTION_KEY no está configurada"
→ Verifica que el `.env` existe y tiene la variable configurada

### "InvalidToken al desencriptar"
→ La clave puede haber cambiado o el archivo está corrupto

### Las imágenes no se muestran en el navegador
→ Verifica los logs de la aplicación para el error específico

## 📖 Más Información

Lee `PHOTO_ENCRYPTION.md` para documentación completa sobre:
- Arquitectura del sistema
- Algoritmos de encriptación usados
- Guías de mantenimiento
- Troubleshooting detallado

---

**¿Todo listo?** ✅ El sistema está completamente implementado y probado. ¡Disfruta de tus fotografías seguras! 🔐
