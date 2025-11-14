import * as Setup from "./store_secret.js";

define(["react", "splunkjs/splunk"], function(react, splunk_js_sdk){
  const e = react.createElement;

  class SetupPage extends react.Component {
    constructor(props) {
      super(props);

      this.state = {
        password: '',
        batching: false,
        batch_size: 10,
      };

      this.handleChange = this.handleChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
    }

    async componentDidMount() {
      try {
        const settings = await Setup.fetchSettings(splunk_js_sdk);
        if (settings) {
          this.setState({
            batching: settings.batching ?? false,
            batch_size: settings.batch_size ?? 10,
          });
        }
      } catch (error) {
        console.error("Failed to load existing CrowdSec settings:", error);
      }
    }

    handleChange(event) {
      const { name, type, checked, value } = event.target;
      const normalizedValue = name === "batch_size" ? parseInt(value, 10) || 10 : value;

      this.setState({ ...this.state, [name]: type === "checkbox" ? checked : normalizedValue })
    }

    async handleSubmit(event) {
      event.preventDefault();

      await Setup.perform(splunk_js_sdk, this.state)
    }
    render() {
      return e("div", null, [
        e("h2", null, "Enter your API key to start using the App!"),
        e("div", null, [
          e("form", { onSubmit: this.handleSubmit }, [
            e("label", null, [
              " ",
              e("input", { type: "text", name: "password", value: this.state.password, placeholder: "Leave empty to keep existing key", onChange: this.handleChange })
            ]),
            e("label", null, [
              " Enable batching",
              e("input", { type: "checkbox", name: "batching", checked: this.state.batching, onChange: this.handleChange })
            ]),
            e("label", null, [
              " Batch size",
              e("select", { name: "batch_size", value: this.state.batch_size, onChange: this.handleChange, disabled: !this.state.batching }, [
                e("option", { value: 10 }, "10"),
                e("option", { value: 20 }, "20"),
                e("option", { value: 50 }, "50"),
                e("option", { value: 100 }, "100")
              ])
            ]),
            e("input", { type: "submit", value: "Submit" })
          ])
        ])
      ]);
    }
  
  }

  return e(SetupPage);
});
