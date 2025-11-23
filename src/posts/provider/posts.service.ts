import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreatePostDto, UpdatePostDto } from '../dto/post.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Post } from '../post.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/user.entity';
import { instanceToInstance, instanceToPlain } from 'class-transformer';

@Injectable()
export class PostsService {
  constructor(
    @InjectRepository(Post)
    private readonly postRepository: Repository<Post>,
  ) {}

  getAllPost() {
    return this.postRepository.find();
  }

  async getPostById(id: number) {
    const post = await this.postRepository.findOneBy({ id });
    if (post) {
      return post;
    }
    throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
  }

  async replacePost(id: number, post: UpdatePostDto) {
    const updateResult = await this.postRepository.update(id, post);

    if (updateResult.affected && updateResult.affected > 0) {
      const updated = await this.postRepository.findOneBy({ id });
      return updated;
    }
    throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
  }

  async getAllPosts() {
    return this.postRepository.find({ relations: ['author'] });
  }

  async createPost(post: CreatePostDto, user: User) {
    const newPost = this.postRepository.create({
      ...post,
      author: user,
    });

    await this.postRepository.save(newPost);
    return {
      id: newPost.id,
      title: newPost.title,
      content: newPost.content,
      authorId: user.id,
    };
  }

  async deletePost(id: number) {
    const result = await this.postRepository.delete(id);
    if (!result.affected) {
      throw new HttpException('Post not found', HttpStatus.NOT_FOUND);
    }
  }
}
