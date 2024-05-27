import { repl } from '@nestjs/core';

import { AppModule } from './app.module';

(async () => await repl(AppModule))();
