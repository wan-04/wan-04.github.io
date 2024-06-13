---
title: House of Husk
date: 2024-06-13 14-23-53
categories: [CTF]
tags: [research, pwn, heap]
math: true
---

## Mô tả

- `House of Husk (HOH)` ảnh hưởng từ libc 2.23 - hiện tại.
- HOH

## Primitive

### Cách sử dụng

- Nếu `__printf_function_table` bằng NULL
- Thay đổi địa chỉ `__printf_arginfo_table` để `__printf_arginfo_table[spec]` bằng one gadget
- Giả sử, ta có `printf("%s\n",a)` thì chương trình sẽ thực thi địa chỉ ở `__printf_arginfo_table[73]`

### register_printf_function

- `register_printf_function` được sử dụng để đăng ký mới một hàm in tuỳ chỉnh
- Hàm `printf` sử dụng các đặc tả có sẵn (%p %s %n) để in ấn. Tuy nhiên nếu chúng ta cần một định dạng mà các đặc tả có sẵn không phù hợp. Khi này, hàm `register_printf_function` được sử dụng để đăng ký một hàm in ấn.
- `register_printf_function` bạn sẽ cần cung cấp 1 con trỏ đến hàm in ấn mới của bạn.
- Trong hàm `__register_printf_specifier` sau, ta thấy có tham số `spec` từ 0x00 - 0xff là kí tự định dạng (ví dụ '%c' thì spec là c)

```c
__register_printf_specifier (int spec, printf_function converter,
			     printf_arginfo_size_function arginfo)
{
  if (spec < 0 || spec > (int) UCHAR_MAX)
    {
      __set_errno (EINVAL);
      return -1;
    }
  int result = 0;
  __libc_lock_lock (lock);
  if (__printf_function_table == NULL)
    {
      __printf_arginfo_table = (printf_arginfo_size_function **)calloc (UCHAR_MAX + 1, sizeof (void *) * 2);
      if (__printf_arginfo_table == NULL)
	{
	  result = -1;
	  goto out;
	}
      __printf_function_table = (printf_function **)(__printf_arginfo_table + UCHAR_MAX + 1);
    }
  __printf_function_table[spec] = converter;
  __printf_arginfo_table[spec] = arginfo;
 out:
  __libc_lock_unlock (lock);
  return result;
}
```

- Hướng tấn công của chung ta sẽ là `printf->vfprintf->printf_positional->__parse_one_specmb`
- Trong `vprintf`, chương trình sẽ kiểm tra `__printf_function_table`. Nếu giá trị là NULL nghĩa là chương trình sẽ sử dụng fast path, sử dụng các đặc tả có sẵn. Nếu giá trị không NULL sẽ sử dụng slow path

```c
  /* Use the slow path in case any printf handler is registered.  */
  if (__glibc_unlikely (__printf_function_table != NULL
                        || __printf_modifier_table != NULL
                        || __printf_va_arg_table != NULL))
    goto do_positional;

```

- Hàm `printf_positional` thực thi `__parse_one_specmb`
- Chúng ta sẽ đưa overwrite địa chỉ `__printf_arginfo_table` thành địa chỉ chứa onegadget

```c
/* Get the format specification.  */
  spec->info.spec = (wchar_t) *format++;
  spec->size = -1;
  if (__builtin_expect (__printf_function_table == NULL, 1)
      || spec->info.spec > UCHAR_MAX
      || __printf_arginfo_table[spec->info.spec] == NULL
      /* We don't try to get the types for all arguments if the format
     uses more than one.  The normal case is covered though.  If
     the call returns -1 we continue with the normal specifiers.  */
      || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
                   (&spec->info, 1, &spec->data_arg_type,
                    &spec->size)) < 0)
    {
      /* Find the data argument types of a built-in spec.  */
      spec->ndata_args = 1;
```

## Tóm lại

- `__printf_function_table` cần khác 0
- `__printf_arginfo_table` overwrite thành địa chỉ chứa onegadget
