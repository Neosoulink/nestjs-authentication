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
import { AuthType } from 'src/iam/authentication/enums/auth-type.enum';
import { ActiveUserData } from '../iam/interfaces/active-user-data.interface';
import { ActiveUser } from '../iam/decorators/active-user.decorator';
import { Roles } from '../iam/authorization/decorators/role.decorator';
import { Auth } from 'src/iam/authentication/decorators/auth.decorator';
import { Permissions } from '../iam/authorization/decorators/permission.decorator';
import { Policies } from '../iam/authorization/decorators/policies.decorator';
import { CoffeesService } from './coffees.service';
import { CreateCoffeeDto } from './dto/create-coffee.dto';
import { UpdateCoffeeDto } from './dto/update-coffee.dto';
import { Permission } from '../iam/authorization/permission.type';
import { FrameworkContributorPolicy } from 'src/iam/authorization/policies/framework-contributor.policy';

@Auth(AuthType.Bearer, AuthType.ApiKey)
@Controller('coffees')
export class CoffeesController {
  constructor(private readonly coffeesService: CoffeesService) {}

  @Roles(Role.Admin)
  @Permissions(Permission.CreateCoffee)
  @Policies(
    new FrameworkContributorPolicy() /** MinAgePolicy(18), new OnlyAdminPolicy() */,
  )
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
  @Policies(new FrameworkContributorPolicy())
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateCoffeeDto: UpdateCoffeeDto) {
    return this.coffeesService.update(+id, updateCoffeeDto);
  }

  @Roles(Role.Admin)
  @Permissions(Permission.DeleteCoffee)
  @Policies(new FrameworkContributorPolicy())
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.coffeesService.remove(+id);
  }
}
