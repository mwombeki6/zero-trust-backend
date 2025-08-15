import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }),
  );
  const config = new DocumentBuilder()
    .setTitle('Zero-Trust')
    .setDescription('Zero-Trust Data Engine')
    .setVersion('1.0')
    .addTag('engine')
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, documentFactory);
  app.enableCors({
    origin: 'http://localhost:5173', // your frontend URL
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    //credentials: true,
  });
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
