import { HttpException, HttpStatus, Injectable, Inject } from '@nestjs/common';
import { CreatePostDto, UpdatePostDto } from './dto/posts.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Post } from './model/post.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/model/user.entity';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class PostsService {
  constructor(
    @InjectRepository(Post)
    private readonly postsRepository: Repository<Post>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async getAllPosts() {
    const cachedPosts = await this.cacheManager.get('posts');

    if (cachedPosts) {
      return cachedPosts;
    }

    const posts = this.postsRepository.find({ relations: ['author'] });

    await this.cacheManager.set('posts', posts);

    return posts;
  }

  async getPostById(id: string) {
    const cacheKey = `post:${id}`;

    const cachedPost = await this.cacheManager.get(cacheKey);

    if (cachedPost) {
      return cachedPost;
    }

    const post = await this.postsRepository.findOneBy({ id });
    if (post) {
      await this.cacheManager.set(cacheKey, post);
      return post;
    }

    throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
  }

  async updatePost(id: string, post: UpdatePostDto) {
    await this.postsRepository.update(id, post);
    const updatedPost = await this.postsRepository.findOneBy({ id });
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

    return this.postsRepository.save(newPost);
  }

  async deletePost(id: string) {
    const deleteResponse = await this.postsRepository.delete(id);
    if (!deleteResponse.affected) {
      throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
    }
  }
}
