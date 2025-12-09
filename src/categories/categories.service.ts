import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import Category from './model/category.entity';
import { Repository } from 'typeorm';

@Injectable()
export class CategoriesService {
  constructor(
    @InjectRepository(Category)
    private readonly categoriesRepository: Repository<Category>,
  ) {}

  getAllCategories() {
    return this.categoriesRepository.find({ relations: ['posts'] });
  }

  async getCategoryById(id: number) {
    const category = await this.categoriesRepository.findOneOrFail({
      where: { id },
      relations: ['products'],
    });
    if (category) {
      return category;
    }
    throw new NotFoundException(id);
  }

  //   async updateCategory(id: number, category: UpdateCategoryDto) {
  //     await this.categoriesRepository.update(id, category);
  //     const updatedCategory = await this.categoriesRepository.findOneOrFail({
  //       where: { id },
  //       relations: ['products'],
  //     });
  //     if (updatedCategory) {
  //       return updatedCategory;
  //     }
  //     throw new NotFoundException(id);
  //   }
}
