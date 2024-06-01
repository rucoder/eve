use cursive;
use anyhow::Result;
use cursive::Cursive;
use cursive::traits::{Nameable, Resizable};
use cursive::views::{Dialog, TextView, EditView};

fn show_popup(s: &mut Cursive, name: &str) {
    if name. is_empty() {
        s. add_layer(Dialog::info("Please enter a name!"));
    } else {
        let content = format!("Hello {}!", name);
        s. pop_layer();
        s. add_layer(Dialog::around(TextView::new(content)).button("Quit", |s| s. quit()));
    }
}
fn main() {
    // Creates the cursive root - required for every application.
    let mut siv = cursive::default();

    // Creates a dialog with a single "Quit" button
    siv. add_layer(
        Dialog::new()
            .title("Enter your name")
            .padding_lrtb(1, 1, 1, 0)
            .content(
                EditView::new()
                    .on_submit(show_popup)
                    .with_name("name")
                    .fixed_width(20),
            )
            .button("Ok", |s| {
                let name = s
                    .call_on_name("name", |view: &mut EditView| view. get_content())
                    .unwrap();
                show_popup(s, &name);
            }),
    );

    // Starts the event loop.
    siv.run();
}

