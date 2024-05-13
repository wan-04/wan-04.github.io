---
title: House of Corrosion
date: 2024-04-26 17-30-56
categories: [CTF]
tags: [pwn, heap, research]
math: true
---

# Giới thiệu

- Ý tưởng của `House of Corrosion` là tận dụng việc ta có thể ghi đè `global_max_fast` gây OOB trong mảng `main_arena.fastbinY`. Bug này từ 2.23 - 2.29

# Ý tưởng

- Đầu tiên ta sẽ xem struct của `main_arena`
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-38-36.png)
- Ta chú ý thấy có một mảng `fastbinY` có chức năng lưu con trỏ ở đầu linked-list của fastbin từ 0x20 đến 0x80
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-43-00.png)
- Ngoài ra, `global_max_fast` là biến toàn cục là giới hạn của `fastbinY`
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-46-10.png)
- Giả sử nếu ta có thể overwrite `global_max_fast` với giá trị lớn hơn nhằm mục đính có thể overwrite các `IO` để leak hoặc get shell thì chúng ta có công thức sau.

```
chunk size = (delta * 2) + 0x20
```

- delta là delta = địa chỉ target - địa chỉ của phần tử đầu tiên của `fastbinY` (`fastbinY[0]`)
- Ví dụ tôi cần overwrite flags của `_IO_2_1_stderr` bằng 1 địa chỉ heap
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-55-49.png)
