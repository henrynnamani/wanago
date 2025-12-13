import {
  HttpException,
  HttpStatus,
  Injectable,
  Inject,
  NotFoundException,
} from '@nestjs/common';
import { CreatePostDto, UpdatePostDto } from './dto/posts.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Post } from './model/post.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/model/user.entity';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';

export enum PrismaError {
  RecordDoesNotExist = 'P2025',
}

@Injectable()
export class PostsService {
  constructor(
    private readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async getAllPosts() {
    const cachedPosts = await this.cacheManager.get('posts');

    if (cachedPosts) {
      return cachedPosts;
    }

    const posts = this.prismaService.post.findMany();

    await this.cacheManager.set('posts', posts);

    return posts;
  }

  async getPostById(id: string) {
    const cacheKey = `post:${id}`;

    const cachedPost = await this.cacheManager.get(cacheKey);

    if (cachedPost) {
      return cachedPost;
    }

    const post = await this.prismaService.post.findUnique({
      where: {
        id,
      },
    });
    if (post) {
      await this.cacheManager.set(cacheKey, post);
      return post;
    }

    throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
  }

  async updatePost(id: string, post: UpdatePostDto) {
    await this.prismaService.post.update({
      data: {
        ...post,
        id: undefined,
      },
      where: {
        id,
      },
    });
    const updatedPost = await this.prismaService.post.findUnique({
      where: { id },
    });
    if (updatedPost) {
      await this.cacheManager.del(`post:${id}`);
      await this.cacheManager.del('posts');
      return updatedPost;
    }

    throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
  }

  async createPost(post: CreatePostDto, user: User) {
    const newPost = this.prismaService.post.create({
      data: post,
    });

    await this.cacheManager.del('posts');

    // return this.postsRepository.save(newPost);
  }

  async deletePost(id: string) {
    try {
      return await this.prismaService.post.delete({
        where: {
          id,
        },
      });
    } catch (err) {
      if (
        err instanceof PrismaClientKnownRequestError &&
        err.code === PrismaError.RecordDoesNotExist
      ) {
        throw new NotFoundException(id);
      }
      throw err;
    }
  }
}
