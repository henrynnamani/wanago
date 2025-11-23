import { Exclude, Transform } from 'class-transformer';
import Category from 'src/category/category.entity';
import { User } from 'src/users/user.entity';
import {
  Column,
  Entity,
  Index,
  JoinTable,
  ManyToMany,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

// @Index(['postId', 'authorId'])
@Entity('posts')
export class Post {
  @PrimaryGeneratedColumn()
  public id: number;

  @Column()
  public title: string;

  @Column()
  public content: string;

  @Column({ nullable: true })
  @Transform((value) => {
    if (value != null) {
      return value;
    }
  })
  public category?: string;

  @Index('post_authorId_index')
  @ManyToOne(() => User, (author: User) => author.posts)
  public author: User;

  @ManyToMany(() => Category)
  @JoinTable()
  public categories: Category[];
}
