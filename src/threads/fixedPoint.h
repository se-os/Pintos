#ifndef FIXED_POINT_H
#define FIXED_POINT_H
//小数位
#define f 1<<14
//常数转换为浮点数格式
#define convert_n_to_fixed_point(n) ((n)*(f))
//向0取整
#define convert_x_to_zero_integer(x) ((x)/(f))
//向最接近的取整
#define convert_x_to_nearest_integer(x) ((x)>=0?((x)+(f)/2)/(f):((x)-(f)/2)/(f))
//浮点数加法
#define add_x_and_y(x,y) ((x)+(y))
//浮点数减法
#define sub_y_from_x(x,y) ((x)-(y))
//加常数(
#define add_x_and_n(x,n) ((x)+(n)*(f))
//减常数
#define sub_n_from_x(x,n) ((x)-(n)*(f))
//浮点数乘法
#define mul_x_by_y(x,y) (((int64_t)(x))*(y)/(f))
//乘常数
#define mul_x_by_n(x,n) ((x)*(n))
//浮点数除法
#define div_x_by_y(x,y) (((int64_t)(x))*(f)/(y))
//除常数
#define div_x_by_n(x,n) ((x)/(n))

#endif