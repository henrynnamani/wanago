import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto, UpdatePostDto } from './dto/posts.dto';
import { JwtAuthGuard } from 'src/auths/guard/jwt.guard';
import { LoggedInUser } from 'src/auths/decorator/current-user.decorator';
import { User } from 'src/users/model/user.entity';
import JwtTwoFactorGuard from 'src/auths/guard/jwt-2fa.guard';

@Controller('posts')
export class PostsController {
  constructor(readonly postsService: PostsService) {}

  @Get()
  getAllPosts() {
    return this.postsService.getAllPosts();
  }

  @Get(':id')
  getPostById(@Param('id') id: string) {
    return this.postsService.getPostById(id);
  }

  @UseGuards(JwtTwoFactorGuard)
  @Post()
  async createPost(@Body() post: CreatePostDto, @LoggedInUser() user: User) {
    return this.postsService.createPost(post, user);
  }

  @Put(':id')
  async replacePost(@Param('id') id: string, @Body() post: UpdatePostDto) {
    return this.postsService.updatePost(id, post);
  }

  @Delete(':id')
  async deletePost(@Param('id') id: string) {
    this.postsService.deletePost(id);
  }
}
