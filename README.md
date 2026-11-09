# N91 Portal

Giao diện điều tra và theo dõi nguồn dữ liệu P16H, P17, OpenStack. Backend FastAPI chạy cùng frontend React.

## Cài trên Proxy Linux

Bản đã build ở [deploy/n91-portal-proxy-linux.tar.gz](deploy/n91-portal-proxy-linux.tar.gz).
Xem [hướng dẫn cài đặt](deploy/proxy/README.md) để chạy Nginx, API, đăng nhập Portal và cấu hình nguồn dữ liệu riêng.

## Build lại frontend và gói Linux

Từ thư mục repo:

    cd fe-api-staging
    npm ci
    npm run build -- --outDir ../deploy/.proxy-web-build --emptyOutDir
    cd ..
    python deploy/build_proxy_bundle.py --output deploy/n91-portal-proxy-linux-new.tar.gz

npm run dev chạy Vite trong lúc phát triển. npm run build tạo file tĩnh cho bản triển khai. Frontend build gọi API qua /api và /api/v1 cùng origin.

## Cập nhật

Trong bản clone, chạy git pull --ff-only để lấy commit mới. Sau đó triển khai gói Linux mới theo hướng dẫn nâng cấp. Việc pull chỉ cập nhật file trong bản clone. Cấu hình và dữ liệu vận hành nằm trong /etc/n91-portal và /var/lib/n91-portal.
