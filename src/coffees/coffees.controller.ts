import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';

import { Role } from '../users/enums/role.enum';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { ActiveUser } from 'src/iam/decorators/active-user.decorator';
import { Roles } from '../iam/authorization/decorators/role.decorator';
import { Permissions } from '../iam/authorization/decorators/permission.decorator';
import { CoffeesService } from './coffees.service';
import { CreateCoffeeDto } from './dto/create-coffee.dto';
import { UpdateCoffeeDto } from './dto/update-coffee.dto';
import { Permission } from 'src/iam/authorization/permission.type';

@Controller('coffees')
export class CoffeesController {
  constructor(private readonly coffeesService: CoffeesService) {}

  @Roles(Role.Admin)
  @Permissions(Permission.CreateCoffee)
  @Post()
  create(@Body() createCoffeeDto: CreateCoffeeDto) {
    return this.coffeesService.create(createCoffeeDto);
  }

  @Get()
  findAll(@ActiveUser() user: ActiveUserData) {
    console.log(user);

    return this.coffeesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.coffeesService.findOne(+id);
  }

  @Roles(Role.Admin)
  @Permissions(Permission.UpdateCoffee)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateCoffeeDto: UpdateCoffeeDto) {
    return this.coffeesService.update(+id, updateCoffeeDto);
  }

  @Roles(Role.Admin)
  @Permissions(Permission.DeleteCoffee)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.coffeesService.remove(+id);
  }
}
