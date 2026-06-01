import type { Preview } from '@storybook/react-vite';
import { withThemeByClassName } from '@storybook/addon-themes';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '../src/index.css';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, staleTime: Infinity } },
});

const preview: Preview = {
  parameters: {
    layout: 'padded',
    backgrounds: { disable: true },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  decorators: [
    // Toggle Tailwind dark mode by adding/removing the `.dark` class on <html>.
    withThemeByClassName({
      themes: { light: '', dark: 'dark' },
      defaultTheme: 'light',
      parentSelector: 'html',
    }),
    // Many of our components use react-router (PageHeader, etc.) and react-query.
    (Story) => (
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <div className="bg-background text-foreground p-4">
            <Story />
          </div>
        </BrowserRouter>
      </QueryClientProvider>
    ),
  ],
};

export default preview;
