https://claude.ai/share/d52e4cf9-2378-483a-b698-d0cf183539cf

Redisの代わりにDBのカラムで2FAコードを管理する実装に変更します。
1. Userエンティティの修正

```java
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String email; // ログインIDとしても使用
    private String passwordHash;
    private String phoneNumber; // SMS 2FA用（オプション）
    
    @Enumerated(EnumType.STRING)
    private TwoFactorMethod twoFactorMethod; // EMAIL or SMS
    
    private boolean twoFactorEnabled = true;
    
    // 2FA認証コード関連のカラム
    private String twoFactorCode; // 認証コード
    
    @Column(name = "two_factor_code_expires_at")
    private LocalDateTime twoFactorCodeExpiresAt; // 有効期限
    
    @Column(name = "two_factor_code_attempts")
    private Integer twoFactorCodeAttempts = 0; // 試行回数（ブルートフォース対策）
    
    // getters/setters
    
    /**
     * 2FAコードが有効かどうかをチェック
     */
    public boolean isTwoFactorCodeValid() {
        return twoFactorCode != null 
            && twoFactorCodeExpiresAt != null 
            && LocalDateTime.now().isBefore(twoFactorCodeExpiresAt)
            && twoFactorCodeAttempts < 5; // 最大5回まで
    }
    
    /**
     * 2FAコードをクリア
     */
    public void clearTwoFactorCode() {
        this.twoFactorCode = null;
        this.twoFactorCodeExpiresAt = null;
        this.twoFactorCodeAttempts = 0;
    }
    
    /**
     * 試行回数をインクリメント
     */
    public void incrementTwoFactorAttempts() {
        this.twoFactorCodeAttempts = (this.twoFactorCodeAttempts == null ? 0 : this.twoFactorCodeAttempts) + 1;
    }
}

public enum TwoFactorMethod {
    EMAIL,
    SMS
}
```

2. マイグレーションSQL（参考）

```sql
ALTER TABLE users 
ADD COLUMN two_factor_code VARCHAR(6),
ADD COLUMN two_factor_code_expires_at TIMESTAMP,
ADD COLUMN two_factor_code_attempts INT DEFAULT 0;

-- インデックス追加（検索性能向上）
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_2fa_expires ON users(two_factor_code_expires_at);
```

3. 2FA認証サービス（DB版）


```java
@Service
@Transactional
public class TwoFactorAuthService {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int CODE_VALIDITY_MINUTES = 5;
    private static final int MAX_ATTEMPTS = 5;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private CognitoSmsService smsService;
    
    @Autowired
    private EmailService emailService;
    
    /**
     * ユーザーの設定に応じて認証コードを送信
     */
    public void sendVerificationCode(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("ユーザーが見つかりません"));
        
        if (!user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FAが有効になっていません");
        }
        
        // 新しいコードを生成
        String code = generateCode();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(CODE_VALIDITY_MINUTES);
        
        // DBに保存
        user.setTwoFactorCode(code);
        user.setTwoFactorCodeExpiresAt(expiresAt);
        user.setTwoFactorCodeAttempts(0); // リセット
        userRepository.save(user);
        
        // ユーザーの設定に応じて送信
        switch (user.getTwoFactorMethod()) {
            case SMS:
                if (user.getPhoneNumber() == null || user.getPhoneNumber().isEmpty()) {
                    throw new IllegalStateException("電話番号が登録されていません");
                }
                smsService.sendSmsCode(user.getPhoneNumber(), code);
                break;
                
            case EMAIL:
                emailService.sendVerificationCode(user.getEmail(), code);
                break;
                
            default:
                throw new IllegalStateException("無効な2FA方式");
        }
    }
    
    /**
     * 認証コードを検証
     */
    public boolean verifyCode(String email, String code) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("ユーザーが見つかりません"));
        
        // 有効期限と試行回数チェック
        if (!user.isTwoFactorCodeValid()) {
            throw new TwoFactorCodeExpiredException("認証コードが期限切れまたは試行回数超過です");
        }
        
        // コード照合
        boolean isValid = code.equals(user.getTwoFactorCode());
        
        if (isValid) {
            // 成功: コードをクリア
            user.clearTwoFactorCode();
            userRepository.save(user);
            return true;
        } else {
            // 失敗: 試行回数をインクリメント
            user.incrementTwoFactorAttempts();
            userRepository.save(user);
            
            if (user.getTwoFactorCodeAttempts() >= MAX_ATTEMPTS) {
                throw new TwoFactorCodeExpiredException("試行回数が上限に達しました。新しいコードを取得してください。");
            }
            
            return false;
        }
    }
    
    /**
     * セキュアな6桁コード生成
     */
    private String generateCode() {
        int code = secureRandom.nextInt(1000000);
        return String.format("%06d", code);
    }
    
    /**
     * どの方式で送信したかを返す（UI表示用）
     */
    public TwoFactorMethod getUserTwoFactorMethod(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("ユーザーが見つかりません"));
        return user.getTwoFactorMethod();
    }
    
    /**
     * 期限切れの2FAコードをクリーンアップ（定期実行推奨）
     */
    @Scheduled(cron = "0 */10 * * * *") // 10分ごと
    public void cleanupExpiredCodes() {
        LocalDateTime now = LocalDateTime.now();
        List<User> expiredUsers = userRepository.findByTwoFactorCodeExpiresAtBefore(now);
        
        for (User user : expiredUsers) {
            user.clearTwoFactorCode();
        }
        
        if (!expiredUsers.isEmpty()) {
            userRepository.saveAll(expiredUsers);
        }
    }
}
```

4. UserRepository（拡張版）

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    
    /**
     * 期限切れの2FAコードを持つユーザーを検索
     */
    @Query("SELECT u FROM User u WHERE u.twoFactorCodeExpiresAt < :expiresAt AND u.twoFactorCode IS NOT NULL")
    List<User> findByTwoFactorCodeExpiresAtBefore(@Param("expiresAt") LocalDateTime expiresAt);
}
```

5. カスタム例外クラス

```java
public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
        super(message);
    }
}

public class TwoFactorCodeExpiredException extends RuntimeException {
    public TwoFactorCodeExpiredException(String message) {
        super(message);
    }
}
```

6. 認証コントローラー（修正版）

```java
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private TwoFactorAuthService twoFactorAuthService;
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Autowired
    private UserRepository userRepository;
    
    /**
     * 第1段階: Email + Password でログイン
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            // パスワード認証
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(), 
                    request.getPassword()
                )
            );
            
            // 認証成功後、2FAコードを送信
            twoFactorAuthService.sendVerificationCode(request.getEmail());
            
            // どの方式で送信したかを取得
            TwoFactorMethod method = twoFactorAuthService.getUserTwoFactorMethod(request.getEmail());
            
            String methodMessage = method == TwoFactorMethod.SMS 
                ? "SMSに認証コードを送信しました" 
                : "メールに認証コードを送信しました";
            
            return ResponseEntity.ok(Map.of(
                "message", methodMessage,
                "twoFactorMethod", method.name(),
                "requiresTwoFactor", true
            ));
            
        } catch (BadCredentialsException e) {
            log.warn("ログイン失敗: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "メールアドレスまたはパスワードが正しくありません"));
        } catch (Exception e) {
            log.error("ログインエラー", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "ログイン処理中にエラーが発生しました"));
        }
    }
    
    /**
     * 第2段階: 2FA認証コードを検証
     */
    @PostMapping("/verify-2fa")
    public ResponseEntity<?> verifyTwoFactor(@Valid @RequestBody TwoFactorRequest request) {
        try {
            boolean isValid = twoFactorAuthService.verifyCode(
                request.getEmail(), 
                request.getCode()
            );
            
            if (isValid) {
                // JWT トークン生成
                String token = tokenProvider.generateToken(request.getEmail());
                
                User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();
                
                return ResponseEntity.ok(Map.of(
                    "token", token,
                    "email", user.getEmail(),
                    "message", "ログインに成功しました"
                ));
            }
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "認証コードが正しくありません"));
                
        } catch (TwoFactorCodeExpiredException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", e.getMessage()));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", e.getMessage()));
        }
    }
    
    /**
     * 2FAコードの再送信
     */
    @PostMapping("/resend-2fa")
    public ResponseEntity<?> resendTwoFactorCode(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        
        try {
            twoFactorAuthService.sendVerificationCode(email);
            
            TwoFactorMethod method = twoFactorAuthService.getUserTwoFactorMethod(email);
            String message = method == TwoFactorMethod.SMS 
                ? "SMSに認証コードを再送信しました" 
                : "メールに認証コードを再送信しました";
            
            return ResponseEntity.ok(Map.of("message", message));
            
        } catch (Exception e) {
            log.error("2FA再送信エラー", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "認証コードの再送信に失敗しました"));
        }
    }
}
```

7. スケジューラ有効化

```java
@Configuration
@EnableScheduling
public class SchedulerConfig {
    // @Scheduled アノテーションを有効化
}
```

8. application.properties

```properties
# Database
spring.datasource.url=jdbc:mysql://localhost:3306/your_database
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.show-sql=true

# AWS Cognito/SNS
aws.cognito.userPoolId=ap-northeast-1_xxxxx
aws.cognito.clientId=xxxxxxxxxxxxx
aws.region=ap-northeast-1

# SMTP設定
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
spring.mail.from=noreply@example.com
```

## 主な変更点とメリット

### DB管理のメリット

- シンプルな構成: Redisサーバーが不要
- トランザクション管理: DBのトランザクションで整合性を保証
- 永続化: サーバー再起動でもコードが失われない
- 監査ログ: 試行回数などの履歴が残る

### セキュリティ機能

- 有効期限: 5分で自動失効
- 試行回数制限: 5回まで（ブルートフォース対策）
- 自動クリーンアップ: 定期的に期限切れコードを削除

### 注意点

- 同時アクセス: 複数デバイスから同時にコード取得すると、最後のコードのみ有効
- パフォーマンス: Redisより若干遅いが、通常のログイン処理では問題なし
- 定期クリーンアップ: @Scheduledで期限切れコードを削除

この実装で、Redisなしでも安全に2FA機能を運用できます。