# Nâng cấp

## 0.13.x → 1.0.0

Bản này gộp **ba** thay đổi phá vỡ vào một lượt, để consumer chỉ phải đổi một lần.

### 1. Gói đổi tên và đổi chủ

| | trước | sau |
|---|---|---|
| repo | `dxs-platform/laravel-auth` | `godx-jp/platform-laravel-auth` |
| gói composer | `dxs/laravel-auth` | `godx-jp/platform-laravel-auth` |

GitHub redirect URL cũ, nên `git clone` và `composer` trỏ URL cũ vẫn chạy — nhưng hãy cập nhật để người sau không phải lần theo một chuyển hướng.

```jsonc
// composer.json của consumer
"repositories": [
    { "type": "vcs", "url": "https://github.com/godx-jp/platform-laravel-auth.git" }
],
"require": {
    "godx-jp/platform-laravel-auth": "^1.0"
}
```

Namespace PHP `Dxs\Auth\` **giữ nguyên** ở 1.0.0 — đổi tên gói và đổi namespace cùng lúc là hai lần đau cho một lần lợi. Namespace sẽ đổi ở một major sau, khi có lý do riêng.

### 2. `Gate::before` không còn trả `false` khi thiếu token

**Đây là thay đổi nặng nhất: nó đổi CÂU TRẢ LỜI phân quyền, không đổi cách hỏi.**

Trước: ability nằm trong `config('authz.permissions')` mà request không mang `console_access_token` ⇒ `Gate::before` trả **`false`** ⇒ `can('<slug>')` deny **mọi người**, kể cả quản trị viên, **im lặng**.

Sau: trả **`null`** ⇒ rơi xuống `Gate::define` / Policy của app.

App nào đang **dựa vào** hành vi deny đó phải khai lại tường minh. Cách kiểm trước khi nâng cấp:

```sh
# mọi chỗ gọi can()/authorize() với một slug trong catalog của bạn
grep -rE "(->can\(|Gate::allows\(|authorize\()\s*['\"]<slug>" app/
```

Không có kết quả ⇒ nâng cấp không đổi hành vi gì.

### 3. Package tự nạp catalog vào Gate và seed xuống DB

`Gate::define` cho mọi slug trong catalog, và seed `permissions` + gán vào role.

**Seeding chỉ chạm slug VỪA SINH.** Bảng `role_permission` là dữ liệu **tổ chức sửa được** ở nhiều consumer; tái áp một giá trị là âm thầm cướp lựa chọn của họ. Guard là `wasRecentlyCreated` trên chính hàng `permissions`, không phải `sync()`.

## Không backport

`0.13.x` đóng băng. Sửa lỗi bảo mật sẽ được xét riêng.
