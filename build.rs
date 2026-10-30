fn main() {
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/ferrite.ico");
        resource
            .compile()
            .expect("compile Windows application icon");
    }
}
