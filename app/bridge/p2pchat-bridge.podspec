Pod::Spec.new do |s|
  s.name = 'p2pchat-bridge'
  s.version = '0.1.0'
  s.summary = 'p2pchat bridge module'
  s.description = 'React Native bridge for the p2pchat core and transport stack.'
  s.homepage = 'https://p2pchat.local'
  s.license = { :type => 'MIT' }
  s.source = { :path => '.' }
  s.platforms = { :ios => '13.0' }

  s.source_files = [
    'ios/**/*.{h,m,mm}',
    'src/**/*.{h,cpp}',
    'include/**/*.{h,hpp}',
    '../../core/identity/src/*.cpp',
    '../../core/crypto/src/*.cpp',
    '../../core/storage/src/*.cpp',
    '../../core/transport/src/*.cpp',
    '../../core/session/src/*.cpp',
    '../../core/core/src/*.cpp'
  ]

  s.public_header_files = 'include/**/*.h'
  s.pod_target_xcconfig = {
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
    'CLANG_CXX_LIBRARY' => 'libc++',
    'HEADER_SEARCH_PATHS' => '"$(PODS_TARGET_SRCROOT)/include" "$(PODS_TARGET_SRCROOT)/../../core/identity/include" "$(PODS_TARGET_SRCROOT)/../../core/crypto/include" "$(PODS_TARGET_SRCROOT)/../../core/storage/include" "$(PODS_TARGET_SRCROOT)/../../core/transport/include" "$(PODS_TARGET_SRCROOT)/../../core/session/include" "$(PODS_TARGET_SRCROOT)/../../core/core/include" "$(PODS_TARGET_SRCROOT)/../../core/security/include"'
  }

  s.frameworks = 'Security', 'CoreFoundation'
  s.libraries = 'sqlite3'
  s.dependency 'OpenSSL-Universal'
end
