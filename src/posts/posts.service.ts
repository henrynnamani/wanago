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
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';
import { trace, context } from '@opentelemetry/api';

export enum PrismaError {
  RecordDoesNotExist = 'P2025',
}

@Injectable()
export class PostsService {
  constructor(
    @InjectRepository(Post)
    private readonly postsRepository: Repository<Post>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async getAllPosts() {
    const tracer = trace.getTracer('nestjs-opentelemetry-demo');

    const span = tracer.startSpan(
      "fetch-posts",
      undefined,
      context.active()
    )
    const cachedPosts = await this.cacheManager.get('posts');

    if (cachedPosts) {
      return cachedPosts;
    }

    const posts = await this.postsRepository.find();
    await this.cacheManager.set('posts', posts);

    span.end();
    
    return posts;
  }

  async getPostById(id: string) {
    const cacheKey = `post:${id}`;

    const cachedPost = await this.cacheManager.get(cacheKey);

    if (cachedPost) {
      return cachedPost;
    }

    const post = await this.postsRepository.findOne({ where: { id } });
    if (post) {
      await this.cacheManager.set(cacheKey, post);
      return post;
    }

    throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
  }

  async updatePost(id: string, post: UpdatePostDto) {
    await this.postsRepository.update(id, post);
    const updatedPost = await this.postsRepository.findOne({
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
    const newPost = this.postsRepository.create({
      ...post,
      author: user,
    });

    await this.cacheManager.del('posts');
  }

  async deletePost(id: string) {
    try {
      return await this.postsRepository.delete(id);
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
