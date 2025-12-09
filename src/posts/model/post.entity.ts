import { Transform } from 'class-transformer';
import Category from 'src/categories/model/category.entity';
import { User } from 'src/users/model/user.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinTable,
  ManyToMany,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('posts')
@Index('IDX_POST_TITLE_SEARCH', ['title'])
@Index('IDX_POSTS_CATEGORY', ['category'])
@Index('IDX_POSTS_AUTHOR_CREATED', ['author', 'createdAt'])
export class Post {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index({ fulltext: true })
  title: string;

  @Column()
  content: string;

  @CreateDateColumn()
  @Index()
  createdAt: Date;

  @Column({ nullable: true })
  @Transform(({ value }) => (value !== null ? value : undefined))
  @Index()
  category?: string;

  @Index('IDX_AUTHOR_ID')
  @ManyToOne(() => User, (user) => user.posts)
  author: User;

  @ManyToMany(() => Category)
  @JoinTable()
  public categories: Category[];
}
