Pod::Spec.new do |s|
  s.name         = "ApproovSession"
  s.version      = "3.5.2"
  s.summary      = "Approov mobile attestation SDK"
  s.description  = <<-DESC
    Approov SDK integrates security attestation and secure string fetching for both iOS and watchOS apps.
  DESC
  s.homepage     = "https://approov.io"
  s.license      = { :type => "Commercial", :file => "LICENSE" }
  s.authors      = { "Approov, Ltd." => "support@approov.io" }
  s.source       = { :git => "https://github.com/approov/approov-service-alamofire", :tag => s.version }
  
  # Supported platforms
  s.ios.deployment_target = '11.0'
  s.watchos.deployment_target = '9.0'

  # Specify the source code paths for the combined target
  s.source_files = "Sources/ApproovSession/**/*.{swift,h}"
  # Dependency on the Approov SDK
  s.dependency 'approov-ios-sdk', '~> 3.5.2'
  s.frameworks = 'Approov'
  # Pod target xcconfig settings if required
  s.pod_target_xcconfig = {
    'VALID_ARCHS' => 'arm64 x86_64 arm64_32 x86_64' # Valid architectures
  }
end
